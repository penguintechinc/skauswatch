"""
Cache Management for SkausWatch Services

Provides comprehensive caching solutions including in-memory, Redis, and
tiered caching with intelligent eviction, metrics, and performance optimization.
"""

import asyncio
import hashlib
import inspect
import json
import logging
import pickle
import threading
import time
import weakref
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    Generic,
    List,
    NamedTuple,
    Optional,
    Set,
    Tuple,
    TypeVar,
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

T = TypeVar("T")
K = TypeVar("K")
V = TypeVar("V")


class CacheBackend(Enum):
    """Cache backend types"""

    MEMORY = "memory"
    REDIS = "redis"
    TIERED = "tiered"


class EvictionPolicy(Enum):
    """Cache eviction policies"""

    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In, First Out
    TTL = "ttl"  # Time To Live only
    RANDOM = "random"


class CacheEvent(Enum):
    """Cache events for monitoring"""

    HIT = "hit"
    MISS = "miss"
    SET = "set"
    DELETE = "delete"
    EXPIRE = "expire"
    EVICT = "evict"
    CLEAR = "clear"


@dataclass
class CacheConfig:
    """Configuration for cache instances"""

    backend: CacheBackend = CacheBackend.MEMORY
    max_size: int = 1000
    default_ttl: float = 300.0  # 5 minutes
    eviction_policy: EvictionPolicy = EvictionPolicy.LRU
    key_prefix: str = ""
    serialization: str = "json"  # json, pickle, raw
    compression: bool = False
    metrics_enabled: bool = True
    health_check_interval: float = 60.0
    auto_cleanup: bool = True
    cleanup_interval: float = 60.0
    redis_url: Optional[str] = None
    redis_db: int = 0
    batch_size: int = 100


@dataclass
class CacheEntry:
    """Cache entry with metadata"""

    key: str
    value: Any
    created_at: float
    last_accessed: float
    access_count: int
    ttl: Optional[float]
    expires_at: Optional[float]
    size_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        """Check if entry has expired"""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    @property
    def age(self) -> float:
        """Get age of entry in seconds"""
        return time.time() - self.created_at

    def touch(self) -> None:
        """Update last accessed time and increment access count"""
        self.last_accessed = time.time()
        self.access_count += 1


class CacheStats(NamedTuple):
    """Cache statistics"""

    hits: int
    misses: int
    sets: int
    deletes: int
    expires: int
    evictions: int
    clears: int
    hit_rate: float
    total_size: int
    entry_count: int
    average_ttl: float
    oldest_entry_age: float


class CacheEventHandler(ABC):
    """Base class for cache event handlers"""

    @abstractmethod
    async def handle_event(self, event: CacheEvent, key: str, **kwargs) -> None:
        """Handle cache event"""
        pass


class MetricsCacheEventHandler(CacheEventHandler):
    """Cache event handler for metrics collection"""

    def __init__(self):
        self.stats = {
            CacheEvent.HIT: 0,
            CacheEvent.MISS: 0,
            CacheEvent.SET: 0,
            CacheEvent.DELETE: 0,
            CacheEvent.EXPIRE: 0,
            CacheEvent.EVICT: 0,
            CacheEvent.CLEAR: 0,
        }
        self.lock = threading.Lock()

    async def handle_event(self, event: CacheEvent, key: str, **kwargs) -> None:
        """Update statistics"""
        with self.lock:
            self.stats[event] += 1

    def get_stats(self) -> Dict[CacheEvent, int]:
        """Get current statistics"""
        with self.lock:
            return self.stats.copy()

    def reset_stats(self) -> None:
        """Reset all statistics"""
        with self.lock:
            for event in self.stats:
                self.stats[event] = 0


class BaseCache(Generic[K, V], ABC):
    """Base cache interface"""

    def __init__(self, name: str, config: CacheConfig):
        self.name = name
        self.config = config
        self.event_handlers: List[CacheEventHandler] = []
        self.metrics_handler = MetricsCacheEventHandler()
        self.event_handlers.append(self.metrics_handler)

    @abstractmethod
    async def get(self, key: K) -> Optional[V]:
        """Get value from cache"""
        pass

    @abstractmethod
    async def set(self, key: K, value: V, ttl: Optional[float] = None) -> bool:
        """Set value in cache"""
        pass

    @abstractmethod
    async def delete(self, key: K) -> bool:
        """Delete value from cache"""
        pass

    @abstractmethod
    async def exists(self, key: K) -> bool:
        """Check if key exists in cache"""
        pass

    @abstractmethod
    async def clear(self) -> None:
        """Clear all cache entries"""
        pass

    @abstractmethod
    async def size(self) -> int:
        """Get number of entries in cache"""
        pass

    @abstractmethod
    async def keys(self) -> List[K]:
        """Get all keys in cache"""
        pass

    async def get_many(self, keys: List[K]) -> Dict[K, Optional[V]]:
        """Get multiple values from cache"""
        result = {}
        for key in keys:
            result[key] = await self.get(key)
        return result

    async def set_many(self, items: Dict[K, V], ttl: Optional[float] = None) -> int:
        """Set multiple values in cache"""
        success_count = 0
        for key, value in items.items():
            if await self.set(key, value, ttl):
                success_count += 1
        return success_count

    async def delete_many(self, keys: List[K]) -> int:
        """Delete multiple values from cache"""
        success_count = 0
        for key in keys:
            if await self.delete(key):
                success_count += 1
        return success_count

    def add_event_handler(self, handler: CacheEventHandler) -> None:
        """Add event handler"""
        self.event_handlers.append(handler)

    def remove_event_handler(self, handler: CacheEventHandler) -> None:
        """Remove event handler"""
        if handler in self.event_handlers:
            self.event_handlers.remove(handler)

    async def _emit_event(self, event: CacheEvent, key: str, **kwargs) -> None:
        """Emit cache event to all handlers"""
        for handler in self.event_handlers:
            try:
                await handler.handle_event(event, key, **kwargs)
            except Exception as e:
                logger.error(f"Cache event handler error: {e}")

    def get_stats(self) -> CacheStats:
        """Get cache statistics"""
        stats = self.metrics_handler.get_stats()
        total_operations = sum(stats.values())
        hits = stats[CacheEvent.HIT]
        misses = stats[CacheEvent.MISS]

        hit_rate = hits / max(1, hits + misses)

        return CacheStats(
            hits=hits,
            misses=misses,
            sets=stats[CacheEvent.SET],
            deletes=stats[CacheEvent.DELETE],
            expires=stats[CacheEvent.EXPIRE],
            evictions=stats[CacheEvent.EVICT],
            clears=stats[CacheEvent.CLEAR],
            hit_rate=hit_rate,
            total_size=0,  # Subclasses should override
            entry_count=0,  # Subclasses should override
            average_ttl=0.0,  # Subclasses should override
            oldest_entry_age=0.0,  # Subclasses should override
        )


class MemoryCache(BaseCache[str, Any]):
    """In-memory cache with configurable eviction policies"""

    def __init__(self, name: str, config: CacheConfig):
        super().__init__(name, config)
        self.entries: Dict[str, CacheEntry] = {}
        self.access_order: List[str] = []  # For LRU
        self.frequency_counter: Dict[str, int] = {}  # For LFU
        self.lock = asyncio.Lock()
        self.cleanup_task: Optional[asyncio.Task] = None

        if config.auto_cleanup:
            self.start_cleanup_task()

    def start_cleanup_task(self) -> None:
        """Start automatic cleanup task"""
        if self.cleanup_task is None:
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop_cleanup_task(self) -> None:
        """Stop automatic cleanup task"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
            self.cleanup_task = None

    async def get(self, key: str) -> Optional[Any]:
        """Get value from memory cache"""
        prefixed_key = self._make_key(key)

        async with self.lock:
            if prefixed_key not in self.entries:
                await self._emit_event(CacheEvent.MISS, key)
                return None

            entry = self.entries[prefixed_key]

            # Check expiration
            if entry.is_expired:
                await self._remove_entry(prefixed_key)
                await self._emit_event(CacheEvent.EXPIRE, key)
                await self._emit_event(CacheEvent.MISS, key)
                return None

            # Update access patterns
            entry.touch()
            self._update_access_tracking(prefixed_key)

            await self._emit_event(CacheEvent.HIT, key)
            return self._deserialize(entry.value)

    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """Set value in memory cache"""
        prefixed_key = self._make_key(key)
        ttl = ttl or self.config.default_ttl

        try:
            serialized_value = self._serialize(value)
            size_bytes = len(str(serialized_value))  # Rough size estimate

            current_time = time.time()
            expires_at = current_time + ttl if ttl > 0 else None

            entry = CacheEntry(
                key=prefixed_key,
                value=serialized_value,
                created_at=current_time,
                last_accessed=current_time,
                access_count=1,
                ttl=ttl,
                expires_at=expires_at,
                size_bytes=size_bytes,
            )

            async with self.lock:
                # Check if we need to evict entries
                if (
                    len(self.entries) >= self.config.max_size
                    and prefixed_key not in self.entries
                ):
                    await self._evict_entries(1)

                # Remove old entry if exists
                if prefixed_key in self.entries:
                    self._remove_from_tracking(prefixed_key)

                # Add new entry
                self.entries[prefixed_key] = entry
                self._add_to_tracking(prefixed_key)

            await self._emit_event(CacheEvent.SET, key, value=value, ttl=ttl)
            return True

        except Exception as e:
            logger.error(f"Error setting cache entry {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete value from memory cache"""
        prefixed_key = self._make_key(key)

        async with self.lock:
            if prefixed_key in self.entries:
                await self._remove_entry(prefixed_key)
                await self._emit_event(CacheEvent.DELETE, key)
                return True

        return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in memory cache"""
        prefixed_key = self._make_key(key)

        async with self.lock:
            if prefixed_key not in self.entries:
                return False

            entry = self.entries[prefixed_key]
            if entry.is_expired:
                await self._remove_entry(prefixed_key)
                await self._emit_event(CacheEvent.EXPIRE, key)
                return False

            return True

    async def clear(self) -> None:
        """Clear all entries from memory cache"""
        async with self.lock:
            self.entries.clear()
            self.access_order.clear()
            self.frequency_counter.clear()

        await self._emit_event(CacheEvent.CLEAR, "")

    async def size(self) -> int:
        """Get number of entries in memory cache"""
        return len(self.entries)

    async def keys(self) -> List[str]:
        """Get all keys in memory cache"""
        async with self.lock:
            # Remove expired entries first
            await self._cleanup_expired()
            return [self._unprefix_key(key) for key in self.entries.keys()]

    async def _evict_entries(self, count: int) -> None:
        """Evict entries based on eviction policy"""
        if not self.entries:
            return

        evicted = 0
        keys_to_evict = []

        if self.config.eviction_policy == EvictionPolicy.LRU:
            # Evict least recently used
            keys_to_evict = self.access_order[:count]

        elif self.config.eviction_policy == EvictionPolicy.LFU:
            # Evict least frequently used
            sorted_by_frequency = sorted(
                self.frequency_counter.items(), key=lambda x: x[1]
            )
            keys_to_evict = [key for key, _ in sorted_by_frequency[:count]]

        elif self.config.eviction_policy == EvictionPolicy.FIFO:
            # Evict oldest entries
            sorted_by_creation = sorted(
                self.entries.items(), key=lambda x: x[1].created_at
            )
            keys_to_evict = [key for key, _ in sorted_by_creation[:count]]

        elif self.config.eviction_policy == EvictionPolicy.RANDOM:
            # Evict random entries
            import random

            all_keys = list(self.entries.keys())
            keys_to_evict = random.sample(all_keys, min(count, len(all_keys)))

        # Remove selected entries
        for key in keys_to_evict:
            if key in self.entries:
                await self._remove_entry(key)
                await self._emit_event(CacheEvent.EVICT, self._unprefix_key(key))
                evicted += 1
                if evicted >= count:
                    break

    async def _remove_entry(self, prefixed_key: str) -> None:
        """Remove entry and update tracking"""
        if prefixed_key in self.entries:
            del self.entries[prefixed_key]
            self._remove_from_tracking(prefixed_key)

    def _add_to_tracking(self, key: str) -> None:
        """Add key to access tracking structures"""
        # LRU tracking
        if key in self.access_order:
            self.access_order.remove(key)
        self.access_order.append(key)

        # LFU tracking
        self.frequency_counter[key] = self.frequency_counter.get(key, 0) + 1

    def _remove_from_tracking(self, key: str) -> None:
        """Remove key from access tracking structures"""
        if key in self.access_order:
            self.access_order.remove(key)
        if key in self.frequency_counter:
            del self.frequency_counter[key]

    def _update_access_tracking(self, key: str) -> None:
        """Update access tracking for a key"""
        # Update LRU order
        if key in self.access_order:
            self.access_order.remove(key)
        self.access_order.append(key)

        # Update LFU counter
        self.frequency_counter[key] = self.frequency_counter.get(key, 0) + 1

    async def _cleanup_loop(self) -> None:
        """Cleanup loop for expired entries"""
        while True:
            try:
                await asyncio.sleep(self.config.cleanup_interval)
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")

    async def _cleanup_expired(self) -> int:
        """Clean up expired entries"""
        current_time = time.time()
        expired_keys = []

        async with self.lock:
            for key, entry in self.entries.items():
                if entry.expires_at and entry.expires_at <= current_time:
                    expired_keys.append(key)

            for key in expired_keys:
                await self._remove_entry(key)
                await self._emit_event(CacheEvent.EXPIRE, self._unprefix_key(key))

        return len(expired_keys)

    def _make_key(self, key: str) -> str:
        """Add prefix to key"""
        return f"{self.config.key_prefix}{key}" if self.config.key_prefix else key

    def _unprefix_key(self, prefixed_key: str) -> str:
        """Remove prefix from key"""
        if self.config.key_prefix and prefixed_key.startswith(self.config.key_prefix):
            return prefixed_key[len(self.config.key_prefix) :]
        return prefixed_key

    def _serialize(self, value: Any) -> Any:
        """Serialize value based on config"""
        if self.config.serialization == "json":
            return json.dumps(value)
        elif self.config.serialization == "pickle":
            return pickle.dumps(value)
        else:  # raw
            return value

    def _deserialize(self, value: Any) -> Any:
        """Deserialize value based on config"""
        if self.config.serialization == "json":
            return json.loads(value)
        elif self.config.serialization == "pickle":
            return pickle.loads(value)
        else:  # raw
            return value

    def get_stats(self) -> CacheStats:
        """Get detailed cache statistics"""
        stats = self.metrics_handler.get_stats()
        hits = stats[CacheEvent.HIT]
        misses = stats[CacheEvent.MISS]
        hit_rate = hits / max(1, hits + misses)

        total_size = sum(entry.size_bytes for entry in self.entries.values())
        entry_count = len(self.entries)

        # Calculate average TTL and oldest entry age
        current_time = time.time()
        ttls = [entry.ttl for entry in self.entries.values() if entry.ttl]
        average_ttl = sum(ttls) / len(ttls) if ttls else 0.0

        ages = [current_time - entry.created_at for entry in self.entries.values()]
        oldest_entry_age = max(ages) if ages else 0.0

        return CacheStats(
            hits=hits,
            misses=misses,
            sets=stats[CacheEvent.SET],
            deletes=stats[CacheEvent.DELETE],
            expires=stats[CacheEvent.EXPIRE],
            evictions=stats[CacheEvent.EVICT],
            clears=stats[CacheEvent.CLEAR],
            hit_rate=hit_rate,
            total_size=total_size,
            entry_count=entry_count,
            average_ttl=average_ttl,
            oldest_entry_age=oldest_entry_age,
        )


class RedisCache(BaseCache[str, Any]):
    """Redis-based cache implementation"""

    def __init__(self, name: str, config: CacheConfig):
        if not HAS_REDIS:
            raise RuntimeError("redis package is required for RedisCache")

        super().__init__(name, config)
        self.redis_client: Optional[aioredis.Redis] = None
        self._connection_pool: Optional[aioredis.ConnectionPool] = None

    async def _ensure_connection(self) -> None:
        """Ensure Redis connection is established"""
        if self.redis_client is None:
            if self.config.redis_url:
                self._connection_pool = aioredis.ConnectionPool.from_url(
                    self.config.redis_url,
                    db=self.config.redis_db,
                    decode_responses=True,
                )
                self.redis_client = aioredis.Redis(
                    connection_pool=self._connection_pool
                )
            else:
                raise ValueError("redis_url must be provided for RedisCache")

    async def get(self, key: str) -> Optional[Any]:
        """Get value from Redis cache"""
        await self._ensure_connection()
        prefixed_key = self._make_key(key)

        try:
            value = await self.redis_client.get(prefixed_key)
            if value is None:
                await self._emit_event(CacheEvent.MISS, key)
                return None

            await self._emit_event(CacheEvent.HIT, key)
            return self._deserialize(value)

        except Exception as e:
            logger.error(f"Redis get error for key {key}: {e}")
            await self._emit_event(CacheEvent.MISS, key)
            return None

    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """Set value in Redis cache"""
        await self._ensure_connection()
        prefixed_key = self._make_key(key)
        ttl = ttl or self.config.default_ttl

        try:
            serialized_value = self._serialize(value)

            if ttl > 0:
                result = await self.redis_client.setex(
                    prefixed_key, int(ttl), serialized_value
                )
            else:
                result = await self.redis_client.set(prefixed_key, serialized_value)

            await self._emit_event(CacheEvent.SET, key, value=value, ttl=ttl)
            return bool(result)

        except Exception as e:
            logger.error(f"Redis set error for key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete value from Redis cache"""
        await self._ensure_connection()
        prefixed_key = self._make_key(key)

        try:
            result = await self.redis_client.delete(prefixed_key)
            if result > 0:
                await self._emit_event(CacheEvent.DELETE, key)
                return True
            return False

        except Exception as e:
            logger.error(f"Redis delete error for key {key}: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in Redis cache"""
        await self._ensure_connection()
        prefixed_key = self._make_key(key)

        try:
            result = await self.redis_client.exists(prefixed_key)
            return bool(result)
        except Exception as e:
            logger.error(f"Redis exists error for key {key}: {e}")
            return False

    async def clear(self) -> None:
        """Clear all entries from Redis cache"""
        await self._ensure_connection()

        try:
            if self.config.key_prefix:
                # Delete keys with prefix
                pattern = f"{self.config.key_prefix}*"
                keys = await self.redis_client.keys(pattern)
                if keys:
                    await self.redis_client.delete(*keys)
            else:
                # Clear entire database (dangerous!)
                await self.redis_client.flushdb()

            await self._emit_event(CacheEvent.CLEAR, "")

        except Exception as e:
            logger.error(f"Redis clear error: {e}")

    async def size(self) -> int:
        """Get number of entries in Redis cache"""
        await self._ensure_connection()

        try:
            if self.config.key_prefix:
                pattern = f"{self.config.key_prefix}*"
                keys = await self.redis_client.keys(pattern)
                return len(keys)
            else:
                return await self.redis_client.dbsize()
        except Exception as e:
            logger.error(f"Redis size error: {e}")
            return 0

    async def keys(self) -> List[str]:
        """Get all keys in Redis cache"""
        await self._ensure_connection()

        try:
            if self.config.key_prefix:
                pattern = f"{self.config.key_prefix}*"
                keys = await self.redis_client.keys(pattern)
                return [self._unprefix_key(key) for key in keys]
            else:
                keys = await self.redis_client.keys("*")
                return keys
        except Exception as e:
            logger.error(f"Redis keys error: {e}")
            return []

    async def get_many(self, keys: List[str]) -> Dict[str, Optional[Any]]:
        """Get multiple values from Redis cache efficiently"""
        await self._ensure_connection()

        if not keys:
            return {}

        prefixed_keys = [self._make_key(key) for key in keys]

        try:
            values = await self.redis_client.mget(*prefixed_keys)
            result = {}

            for i, (key, value) in enumerate(zip(keys, values)):
                if value is not None:
                    result[key] = self._deserialize(value)
                    await self._emit_event(CacheEvent.HIT, key)
                else:
                    result[key] = None
                    await self._emit_event(CacheEvent.MISS, key)

            return result

        except Exception as e:
            logger.error(f"Redis get_many error: {e}")
            return {key: None for key in keys}

    async def set_many(self, items: Dict[str, Any], ttl: Optional[float] = None) -> int:
        """Set multiple values in Redis cache efficiently"""
        await self._ensure_connection()

        if not items:
            return 0

        ttl = ttl or self.config.default_ttl
        success_count = 0

        try:
            # Use pipeline for efficiency
            pipe = self.redis_client.pipeline()

            for key, value in items.items():
                prefixed_key = self._make_key(key)
                serialized_value = self._serialize(value)

                if ttl > 0:
                    pipe.setex(prefixed_key, int(ttl), serialized_value)
                else:
                    pipe.set(prefixed_key, serialized_value)

            results = await pipe.execute()

            for i, (key, result) in enumerate(zip(items.keys(), results)):
                if result:
                    success_count += 1
                    await self._emit_event(
                        CacheEvent.SET, key, value=items[key], ttl=ttl
                    )

            return success_count

        except Exception as e:
            logger.error(f"Redis set_many error: {e}")
            return 0

    async def close(self) -> None:
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
        if self._connection_pool:
            await self._connection_pool.disconnect()

    def _make_key(self, key: str) -> str:
        """Add prefix to key"""
        return f"{self.config.key_prefix}{key}" if self.config.key_prefix else key

    def _unprefix_key(self, prefixed_key: str) -> str:
        """Remove prefix from key"""
        if self.config.key_prefix and prefixed_key.startswith(self.config.key_prefix):
            return prefixed_key[len(self.config.key_prefix) :]
        return prefixed_key

    def _serialize(self, value: Any) -> str:
        """Serialize value for Redis storage"""
        if self.config.serialization == "json":
            return json.dumps(value)
        elif self.config.serialization == "pickle":
            return pickle.dumps(value).hex()  # Convert bytes to hex string
        else:  # raw - assume string
            return str(value)

    def _deserialize(self, value: str) -> Any:
        """Deserialize value from Redis storage"""
        if self.config.serialization == "json":
            return json.loads(value)
        elif self.config.serialization == "pickle":
            return pickle.loads(bytes.fromhex(value))
        else:  # raw
            return value


class TieredCache(BaseCache[str, Any]):
    """Tiered cache with L1 (memory) and L2 (Redis) layers"""

    def __init__(self, name: str, l1_config: CacheConfig, l2_config: CacheConfig):
        # Use L1 config as primary config
        super().__init__(name, l1_config)

        # Create L1 (memory) and L2 (Redis) caches
        self.l1_cache = MemoryCache(f"{name}_l1", l1_config)
        self.l2_cache = RedisCache(f"{name}_l2", l2_config)

        # Tier-specific configurations
        self.l1_promotion_threshold = 2  # Promote to L1 after N accesses
        self.promotion_counters: Dict[str, int] = {}
        self.promotion_lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        """Get value from tiered cache (L1 first, then L2)"""
        # Try L1 first
        value = await self.l1_cache.get(key)
        if value is not None:
            return value

        # Try L2
        value = await self.l2_cache.get(key)
        if value is not None:
            # Track access for potential promotion to L1
            await self._track_access_for_promotion(key, value)
            return value

        # Not found in either tier
        await self._emit_event(CacheEvent.MISS, key)
        return None

    async def set(self, key: str, value: Any, ttl: Optional[float] = None) -> bool:
        """Set value in both tiers"""
        # Set in both L1 and L2
        l1_success = await self.l1_cache.set(key, value, ttl)
        l2_success = await self.l2_cache.set(key, value, ttl)

        success = l1_success or l2_success
        if success:
            await self._emit_event(CacheEvent.SET, key, value=value, ttl=ttl)

        return success

    async def delete(self, key: str) -> bool:
        """Delete value from both tiers"""
        l1_deleted = await self.l1_cache.delete(key)
        l2_deleted = await self.l2_cache.delete(key)

        # Remove from promotion tracking
        async with self.promotion_lock:
            self.promotion_counters.pop(key, None)

        success = l1_deleted or l2_deleted
        if success:
            await self._emit_event(CacheEvent.DELETE, key)

        return success

    async def exists(self, key: str) -> bool:
        """Check if key exists in either tier"""
        return await self.l1_cache.exists(key) or await self.l2_cache.exists(key)

    async def clear(self) -> None:
        """Clear both tiers"""
        await self.l1_cache.clear()
        await self.l2_cache.clear()

        async with self.promotion_lock:
            self.promotion_counters.clear()

        await self._emit_event(CacheEvent.CLEAR, "")

    async def size(self) -> int:
        """Get total number of unique entries across tiers"""
        l1_keys = set(await self.l1_cache.keys())
        l2_keys = set(await self.l2_cache.keys())
        return len(l1_keys | l2_keys)

    async def keys(self) -> List[str]:
        """Get all unique keys across tiers"""
        l1_keys = set(await self.l1_cache.keys())
        l2_keys = set(await self.l2_cache.keys())
        return list(l1_keys | l2_keys)

    async def _track_access_for_promotion(self, key: str, value: Any) -> None:
        """Track access count for potential promotion to L1"""
        async with self.promotion_lock:
            self.promotion_counters[key] = self.promotion_counters.get(key, 0) + 1

            # Promote to L1 if access threshold reached
            if self.promotion_counters[key] >= self.l1_promotion_threshold:
                await self.l1_cache.set(key, value)
                del self.promotion_counters[key]
                logger.debug(f"Promoted key {key} to L1 cache")

    async def close(self) -> None:
        """Close both cache tiers"""
        await self.l1_cache.stop_cleanup_task()
        await self.l2_cache.close()

    def get_tier_stats(self) -> Dict[str, CacheStats]:
        """Get statistics for both cache tiers"""
        return {"l1": self.l1_cache.get_stats(), "l2": self.l2_cache.get_stats()}


class CacheManager:
    """Centralized cache management"""

    def __init__(self):
        self.caches: Dict[str, BaseCache] = {}
        self.default_config = CacheConfig()

    def create_memory_cache(
        self, name: str, config: Optional[CacheConfig] = None
    ) -> MemoryCache:
        """Create memory cache"""
        if name in self.caches:
            raise ValueError(f"Cache '{name}' already exists")

        config = config or self.default_config
        cache = MemoryCache(name, config)
        self.caches[name] = cache

        return cache

    def create_redis_cache(
        self, name: str, redis_url: str, config: Optional[CacheConfig] = None
    ) -> RedisCache:
        """Create Redis cache"""
        if name in self.caches:
            raise ValueError(f"Cache '{name}' already exists")

        config = config or self.default_config
        config.redis_url = redis_url
        cache = RedisCache(name, config)
        self.caches[name] = cache

        return cache

    def create_tiered_cache(
        self,
        name: str,
        redis_url: str,
        l1_config: Optional[CacheConfig] = None,
        l2_config: Optional[CacheConfig] = None,
    ) -> TieredCache:
        """Create tiered cache"""
        if name in self.caches:
            raise ValueError(f"Cache '{name}' already exists")

        l1_config = l1_config or CacheConfig(backend=CacheBackend.MEMORY)
        l2_config = l2_config or CacheConfig(
            backend=CacheBackend.REDIS, redis_url=redis_url
        )

        cache = TieredCache(name, l1_config, l2_config)
        self.caches[name] = cache

        return cache

    def get_cache(self, name: str) -> Optional[BaseCache]:
        """Get cache by name"""
        return self.caches.get(name)

    async def close_all(self) -> None:
        """Close all caches"""
        for cache in self.caches.values():
            if hasattr(cache, "close"):
                await cache.close()
            elif hasattr(cache, "stop_cleanup_task"):
                await cache.stop_cleanup_task()

        self.caches.clear()

    def get_all_stats(self) -> Dict[str, Union[CacheStats, Dict[str, CacheStats]]]:
        """Get statistics for all caches"""
        stats = {}
        for name, cache in self.caches.items():
            if isinstance(cache, TieredCache):
                stats[name] = cache.get_tier_stats()
            else:
                stats[name] = cache.get_stats()
        return stats


# Cache decorators


def cache_key_generator(*args, **kwargs) -> str:
    """Generate cache key from function arguments"""
    key_parts = []

    # Add positional arguments
    for arg in args:
        if hasattr(arg, "__dict__"):
            # For objects, use class name and id
            key_parts.append(f"{arg.__class__.__name__}_{id(arg)}")
        else:
            key_parts.append(str(arg))

    # Add keyword arguments
    for key, value in sorted(kwargs.items()):
        key_parts.append(f"{key}_{value}")

    # Create hash for consistent key length
    key_string = "|".join(key_parts)
    return hashlib.md5(key_string.encode()).hexdigest()


def cache_decorator(
    cache_name: str = "default",
    ttl: Optional[float] = None,
    key_prefix: str = "",
    key_generator: Optional[Callable] = None,
    cache_manager: Optional[CacheManager] = None,
):
    """Decorator to cache function results"""

    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            nonlocal cache_manager
            if cache_manager is None:
                cache_manager = get_global_cache_manager()

            cache = cache_manager.get_cache(cache_name)
            if cache is None:
                # Create default memory cache
                cache = cache_manager.create_memory_cache(cache_name)

            # Generate cache key
            if key_generator:
                cache_key = key_generator(*args, **kwargs)
            else:
                cache_key = cache_key_generator(*args, **kwargs)

            if key_prefix:
                cache_key = f"{key_prefix}_{cache_key}"

            # Try to get from cache
            cached_result = await cache.get(cache_key)
            if cached_result is not None:
                return cached_result

            # Execute function and cache result
            result = await func(*args, **kwargs)
            await cache.set(cache_key, result, ttl)

            return result

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For synchronous functions, we can't use async cache
            # This is a limitation - consider using synchronous cache
            return func(*args, **kwargs)

        # Return appropriate wrapper based on function type
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


async def invalidate_cache(
    cache_name: str,
    key: Optional[str] = None,
    pattern: Optional[str] = None,
    cache_manager: Optional[CacheManager] = None,
) -> bool:
    """Invalidate cache entries"""
    cache_manager = cache_manager or get_global_cache_manager()
    cache = cache_manager.get_cache(cache_name)

    if cache is None:
        return False

    if key:
        return await cache.delete(key)
    elif pattern:
        # For pattern-based invalidation, we need to get all keys and filter
        all_keys = await cache.keys()
        deleted_count = 0

        import fnmatch

        for cache_key in all_keys:
            if fnmatch.fnmatch(cache_key, pattern):
                if await cache.delete(cache_key):
                    deleted_count += 1

        return deleted_count > 0
    else:
        # Clear entire cache
        await cache.clear()
        return True


# Global cache manager
_global_cache_manager: Optional[CacheManager] = None


def get_global_cache_manager() -> CacheManager:
    """Get global cache manager instance"""
    global _global_cache_manager
    if _global_cache_manager is None:
        _global_cache_manager = CacheManager()
    return _global_cache_manager


async def cleanup_global_caches():
    """Cleanup global caches"""
    global _global_cache_manager
    if _global_cache_manager is not None:
        await _global_cache_manager.close_all()
        _global_cache_manager = None
