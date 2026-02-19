"""
SkausWatch AAA Monitor Service - Threat Database

Local threat intelligence database for storing and managing IOCs,
with support for both SQLite and Redis backends.
"""

import asyncio
import json
import logging
import sqlite3
import hashlib
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
import aiosqlite
from contextlib import asynccontextmanager
from dataclasses import dataclass
from collections import defaultdict

import structlog
import redis.asyncio as redis
from tenacity import retry, stop_after_attempt, wait_exponential

from ..models import IOC, ThreatFeed, ThreatLevel

logger = structlog.get_logger(__name__)


@dataclass
class QueryOptimization:
    """Query optimization metadata"""

    use_index: bool = True
    index_hint: Optional[str] = None
    limit_optimization: bool = True
    cache_result: bool = True
    cache_ttl: int = 3600


class QueryOptimizer:
    """Optimizes database queries for better performance"""

    def __init__(self):
        self.query_cache = {}
        self.execution_plans = {}

    def optimize_query(
        self, query: str, params: Tuple
    ) -> Tuple[str, Tuple, QueryOptimization]:
        """Optimize query for better performance"""
        optimization = QueryOptimization()

        # Add query hints based on patterns
        if "WHERE type = ?" in query and "AND value = ?" in query:
            optimization.index_hint = "idx_indicators_type_value"
        elif "WHERE threat_level" in query:
            optimization.index_hint = "idx_indicators_threat_level"
        elif "ORDER BY created_at" in query:
            optimization.index_hint = "idx_indicators_created_at"

        return query, params, optimization


class ThreatIntelligenceCache:
    """Advanced caching layer for threat intelligence data"""

    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client
        self.local_cache = {}
        self.cache_stats = {"hits": 0, "misses": 0, "evictions": 0, "size": 0}
        self.max_local_cache_size = 10000
        self.default_ttl = 3600  # 1 hour

    async def get(self, key: str, default=None) -> Any:
        """Get cached value with fallback"""
        try:
            # Try Redis first
            if self.redis_client:
                value = await self.redis_client.get(f"threat_cache:{key}")
                if value:
                    self.cache_stats["hits"] += 1
                    return json.loads(value)

            # Try local cache
            if key in self.local_cache:
                entry = self.local_cache[key]
                if entry["expires"] > time.time():
                    self.cache_stats["hits"] += 1
                    return entry["data"]
                else:
                    # Expired
                    del self.local_cache[key]

            self.cache_stats["misses"] += 1
            return default

        except Exception as e:
            logger.error("Error getting cached value", key=key, error=str(e))
            return default

    async def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """Set cached value in both Redis and local cache"""
        try:
            ttl = ttl or self.default_ttl

            # Set in Redis
            if self.redis_client:
                await self.redis_client.setex(
                    f"threat_cache:{key}", ttl, json.dumps(value, default=str)
                )

            # Set in local cache with size management
            if len(self.local_cache) >= self.max_local_cache_size:
                # Remove oldest entries
                oldest_keys = sorted(
                    self.local_cache.keys(),
                    key=lambda k: self.local_cache[k]["created"],
                )[
                    :100
                ]  # Remove 100 oldest

                for old_key in oldest_keys:
                    del self.local_cache[old_key]
                    self.cache_stats["evictions"] += 1

            self.local_cache[key] = {
                "data": value,
                "created": time.time(),
                "expires": time.time() + ttl,
            }

            self.cache_stats["size"] = len(self.local_cache)
            return True

        except Exception as e:
            logger.error("Error setting cached value", key=key, error=str(e))
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        hit_rate = 0.0
        total_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
        if total_requests > 0:
            hit_rate = self.cache_stats["hits"] / total_requests

        return {
            **self.cache_stats,
            "hit_rate": hit_rate,
            "local_cache_size": len(self.local_cache),
        }


class ThreatDatabase:
    """High-performance threat intelligence database with advanced indexing and caching"""

    def __init__(self, database_path: str, redis_client: Optional[redis.Redis] = None):
        """Initialize enhanced threat database

        Args:
            database_path: Path to SQLite database file
            redis_client: Optional Redis client for caching
        """
        self.database_path = Path(database_path)
        self.redis_client = redis_client

        # Advanced caching layer
        self.cache = ThreatIntelligenceCache(redis_client)

        # Connection pool for better concurrent access
        self._connection_semaphore = asyncio.Semaphore(
            20
        )  # Max 20 concurrent connections

        # Query optimization
        self.query_optimizer = QueryOptimizer()

        # Batch processing
        self.batch_size = 1000
        self.batch_queue = asyncio.Queue(maxsize=10000)
        self.batch_processor_running = False

        # Ensure database directory exists
        self.database_path.parent.mkdir(parents=True, exist_ok=True)

        # Database connection pool
        self.db_pool_size = 10
        self.db_connections = []
        self.db_lock = asyncio.Lock()

        # Redis key prefixes
        self.redis_prefixes = {
            "indicator": "threat:indicator:",
            "feed": "threat:feed:",
            "stats": "threat:stats:",
            "cache": "threat:cache:",
        }

        # Enhanced statistics with performance metrics
        self.stats = {
            "total_indicators": 0,
            "indicators_by_type": {},
            "indicators_by_threat_level": {},
            "last_update": None,
            "database_size": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "query_performance": {
                "avg_query_time": 0.0,
                "slow_queries": 0,
                "optimized_queries": 0,
                "index_usage": {},
            },
            "batch_processing": {
                "batches_processed": 0,
                "indicators_batched": 0,
                "avg_batch_time": 0.0,
            },
            "deduplication": {
                "duplicates_found": 0,
                "duplicates_merged": 0,
                "unique_indicators": 0,
            },
        }

        # Performance monitoring
        self.query_times = []
        self.max_query_history = 1000

        # Cache TTL (seconds)
        self.cache_ttl = 3600  # 1 hour

        # Deduplication settings
        self.enable_deduplication = True
        self.similarity_threshold = 0.95

        # Background tasks
        self._cleanup_task = None
        self._batch_processor_task = None
        self._index_optimization_task = None

    async def initialize(self):
        """Initialize enhanced threat database with performance optimizations"""
        try:
            # Create database schema with enhanced indexes
            await self._create_enhanced_schema()

            # Initialize database connection pool
            await self._init_connection_pool()

            # Create performance indexes
            await self._create_performance_indexes()

            # Load statistics with enhanced metrics
            await self._load_enhanced_statistics()

            # Test Redis connection and initialize cache
            if self.redis_client:
                await self.redis_client.ping()
                logger.info("Redis connection verified for threat database")

            # Start background tasks
            await self._start_background_tasks()

            # Analyze and optimize database
            await self._analyze_database()

            logger.info(
                "Enhanced threat database initialized successfully",
                database_path=str(self.database_path),
                total_indicators=self.stats["total_indicators"],
                cache_enabled=self.redis_client is not None,
                deduplication_enabled=self.enable_deduplication,
            )

        except Exception as e:
            logger.error("Failed to initialize enhanced threat database", error=str(e))
            raise

    async def _create_schema(self):
        """Create database schema"""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                # Indicators table
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS indicators (
                        id TEXT PRIMARY KEY,
                        type TEXT NOT NULL,
                        value TEXT NOT NULL,
                        description TEXT,
                        threat_level TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        source TEXT,
                        tags TEXT,  -- JSON array
                        malware_families TEXT,  -- JSON array
                        kill_chain_phases TEXT,  -- JSON array
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        expires_at TEXT,
                        first_seen TEXT,
                        last_seen TEXT,
                        hit_count INTEGER DEFAULT 0
                    )
                """)

                # Create indexes for performance
                await db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_indicators_type_value 
                    ON indicators (type, value)
                """)

                await db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_indicators_threat_level 
                    ON indicators (threat_level)
                """)

                await db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_indicators_source 
                    ON indicators (source)
                """)

                await db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_indicators_created_at 
                    ON indicators (created_at)
                """)

                # Feeds table
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS feeds (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        url TEXT NOT NULL,
                        feed_type TEXT NOT NULL,
                        enabled INTEGER NOT NULL DEFAULT 1,
                        last_update TEXT,
                        last_success TEXT,
                        last_error TEXT,
                        indicator_count INTEGER DEFAULT 0,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)

                # Matches table for tracking IOC hits
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS matches (
                        id TEXT PRIMARY KEY,
                        indicator_id TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        matched_value TEXT NOT NULL,
                        field_name TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (indicator_id) REFERENCES indicators (id)
                    )
                """)

                await db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_matches_indicator_id 
                    ON matches (indicator_id)
                """)

                await db.execute("""
                    CREATE INDEX IF NOT EXISTS idx_matches_timestamp 
                    ON matches (timestamp)
                """)

                await db.commit()

            logger.info("Database schema created/updated successfully")

        except Exception as e:
            logger.error("Error creating database schema", error=str(e))
            raise

    async def _init_connection_pool(self):
        """Initialize database connection pool"""
        try:
            # For SQLite, we'll manage connections differently
            # as SQLite doesn't support true connection pooling
            pass

        except Exception as e:
            logger.error("Error initializing connection pool", error=str(e))
            raise

    async def _load_statistics(self):
        """Load database statistics"""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                # Total indicators
                cursor = await db.execute("SELECT COUNT(*) FROM indicators")
                row = await cursor.fetchone()
                self.stats["total_indicators"] = row[0] if row else 0

                # Indicators by type
                cursor = await db.execute("""
                    SELECT type, COUNT(*) FROM indicators GROUP BY type
                """)
                async for row in cursor:
                    self.stats["indicators_by_type"][row[0]] = row[1]

                # Indicators by threat level
                cursor = await db.execute("""
                    SELECT threat_level, COUNT(*) FROM indicators GROUP BY threat_level
                """)
                async for row in cursor:
                    self.stats["indicators_by_threat_level"][row[0]] = row[1]

                # Database file size
                self.stats["database_size"] = self.database_path.stat().st_size

        except Exception as e:
            logger.error("Error loading statistics", error=str(e))

    async def store_indicator(self, ioc: IOC) -> bool:
        """Store indicator in database

        Args:
            ioc: Indicator to store

        Returns:
            True if stored successfully
        """
        try:
            async with aiosqlite.connect(self.database_path) as db:
                # Check if indicator already exists
                cursor = await db.execute(
                    """
                    SELECT id, hit_count FROM indicators WHERE type = ? AND value = ?
                """,
                    (ioc.type, ioc.value),
                )

                existing = await cursor.fetchone()

                if existing:
                    # Update existing indicator
                    await db.execute(
                        """
                        UPDATE indicators SET
                            description = ?,
                            threat_level = ?,
                            confidence = ?,
                            source = ?,
                            tags = ?,
                            malware_families = ?,
                            kill_chain_phases = ?,
                            updated_at = ?,
                            expires_at = ?,
                            last_seen = ?
                        WHERE id = ?
                    """,
                        (
                            ioc.description,
                            ioc.threat_level.value,
                            ioc.confidence,
                            ioc.source,
                            json.dumps(ioc.tags),
                            json.dumps(ioc.malware_families),
                            json.dumps(ioc.kill_chain_phases),
                            ioc.updated_at.isoformat(),
                            ioc.expiration.isoformat() if ioc.expiration else None,
                            datetime.utcnow().isoformat(),
                            existing[0],
                        ),
                    )

                    logger.debug(
                        "Indicator updated",
                        ioc_id=existing[0],
                        type=ioc.type,
                        value=ioc.value,
                    )

                else:
                    # Insert new indicator
                    await db.execute(
                        """
                        INSERT INTO indicators (
                            id, type, value, description, threat_level, confidence,
                            source, tags, malware_families, kill_chain_phases,
                            created_at, updated_at, expires_at, first_seen, last_seen
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            ioc.id,
                            ioc.type,
                            ioc.value,
                            ioc.description,
                            ioc.threat_level.value,
                            ioc.confidence,
                            ioc.source,
                            json.dumps(ioc.tags),
                            json.dumps(ioc.malware_families),
                            json.dumps(ioc.kill_chain_phases),
                            ioc.created_at.isoformat(),
                            ioc.updated_at.isoformat(),
                            ioc.expiration.isoformat() if ioc.expiration else None,
                            datetime.utcnow().isoformat(),
                            datetime.utcnow().isoformat(),
                        ),
                    )

                    # Update statistics
                    self.stats["total_indicators"] += 1
                    self.stats["indicators_by_type"][ioc.type] = (
                        self.stats["indicators_by_type"].get(ioc.type, 0) + 1
                    )
                    self.stats["indicators_by_threat_level"][ioc.threat_level.value] = (
                        self.stats["indicators_by_threat_level"].get(
                            ioc.threat_level.value, 0
                        )
                        + 1
                    )

                    logger.debug(
                        "New indicator stored",
                        ioc_id=ioc.id,
                        type=ioc.type,
                        value=ioc.value,
                    )

                await db.commit()

                # Cache in Redis if available
                if self.redis_client:
                    await self._cache_indicator(ioc)

                return True

        except Exception as e:
            logger.error("Error storing indicator", ioc_id=ioc.id, error=str(e))
            return False

    async def _cache_indicator(self, ioc: IOC):
        """Cache indicator in Redis"""
        try:
            key = f"{self.redis_prefixes['indicator']}{ioc.type}:{ioc.value}"
            value = {
                "id": ioc.id,
                "type": ioc.type,
                "value": ioc.value,
                "description": ioc.description,
                "threat_level": ioc.threat_level.value,
                "confidence": ioc.confidence,
                "source": ioc.source,
                "tags": ioc.tags,
                "malware_families": ioc.malware_families,
                "kill_chain_phases": ioc.kill_chain_phases,
                "created_at": ioc.created_at.isoformat(),
                "updated_at": ioc.updated_at.isoformat(),
            }

            await self.redis_client.setex(
                key, self.cache_ttl, json.dumps(value, default=str)
            )

        except Exception as e:
            logger.error("Error caching indicator", error=str(e))

    async def search_indicators(self, indicator_type: str, value: str) -> List[IOC]:
        """Search for indicators by type and value

        Args:
            indicator_type: Type of indicator to search for
            value: Value to match

        Returns:
            List of matching IOCs
        """
        try:
            # Check Redis cache first
            if self.redis_client:
                cached = await self._get_cached_indicator(indicator_type, value)
                if cached:
                    self.stats["cache_hits"] += 1
                    return [cached]
                else:
                    self.stats["cache_misses"] += 1

            # Search database
            indicators = []

            async with aiosqlite.connect(self.database_path) as db:
                cursor = await db.execute(
                    """
                    SELECT id, type, value, description, threat_level, confidence,
                           source, tags, malware_families, kill_chain_phases,
                           created_at, updated_at, expires_at
                    FROM indicators 
                    WHERE type = ? AND value = ?
                    AND (expires_at IS NULL OR expires_at > ?)
                """,
                    (indicator_type, value, datetime.utcnow().isoformat()),
                )

                async for row in cursor:
                    ioc = self._row_to_ioc(row)
                    if ioc:
                        indicators.append(ioc)

                        # Update hit count
                        await db.execute(
                            """
                            UPDATE indicators SET 
                                hit_count = hit_count + 1,
                                last_seen = ?
                            WHERE id = ?
                        """,
                            (datetime.utcnow().isoformat(), ioc.id),
                        )

                await db.commit()

            # Cache results if found
            if indicators and self.redis_client:
                for ioc in indicators:
                    await self._cache_indicator(ioc)

            return indicators

        except Exception as e:
            logger.error(
                "Error searching indicators",
                type=indicator_type,
                value=value,
                error=str(e),
            )
            return []

    async def _get_cached_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[IOC]:
        """Get cached indicator from Redis"""
        try:
            key = f"{self.redis_prefixes['indicator']}{indicator_type}:{value}"
            cached_data = await self.redis_client.get(key)

            if cached_data:
                data = json.loads(cached_data)
                return IOC(
                    id=data["id"],
                    type=data["type"],
                    value=data["value"],
                    description=data.get("description"),
                    threat_level=ThreatLevel(data["threat_level"]),
                    confidence=data["confidence"],
                    source=data.get("source"),
                    tags=data.get("tags", []),
                    malware_families=data.get("malware_families", []),
                    kill_chain_phases=data.get("kill_chain_phases", []),
                    created_at=datetime.fromisoformat(data["created_at"]),
                    updated_at=datetime.fromisoformat(data["updated_at"]),
                )

            return None

        except Exception as e:
            logger.error("Error getting cached indicator", error=str(e))
            return None

    def _row_to_ioc(self, row: Tuple) -> Optional[IOC]:
        """Convert database row to IOC object"""
        try:
            return IOC(
                id=row[0],
                type=row[1],
                value=row[2],
                description=row[3],
                threat_level=ThreatLevel(row[4]),
                confidence=row[5],
                source=row[6],
                tags=json.loads(row[7]) if row[7] else [],
                malware_families=json.loads(row[8]) if row[8] else [],
                kill_chain_phases=json.loads(row[9]) if row[9] else [],
                created_at=datetime.fromisoformat(row[10]),
                updated_at=datetime.fromisoformat(row[11]),
                expiration=datetime.fromisoformat(row[12]) if row[12] else None,
            )

        except Exception as e:
            logger.error("Error converting row to IOC", error=str(e))
            return None

    async def search_similar_indicators(
        self, indicator_type: str, value: str, threshold: float = 0.8
    ) -> List[IOC]:
        """Search for similar indicators using fuzzy matching

        Args:
            indicator_type: Type of indicator
            value: Value to find similar matches for
            threshold: Similarity threshold (0.0 to 1.0)

        Returns:
            List of similar IOCs
        """
        try:
            indicators = []

            async with aiosqlite.connect(self.database_path) as db:
                # Get all indicators of the same type for similarity comparison
                cursor = await db.execute(
                    """
                    SELECT id, type, value, description, threat_level, confidence,
                           source, tags, malware_families, kill_chain_phases,
                           created_at, updated_at, expires_at
                    FROM indicators 
                    WHERE type = ?
                    AND (expires_at IS NULL OR expires_at > ?)
                """,
                    (indicator_type, datetime.utcnow().isoformat()),
                )

                async for row in cursor:
                    stored_value = row[2]

                    # Calculate similarity
                    similarity = self._calculate_similarity(value, stored_value)

                    if (
                        similarity >= threshold and similarity < 1.0
                    ):  # Exclude exact matches
                        ioc = self._row_to_ioc(row)
                        if ioc:
                            # Adjust confidence based on similarity
                            ioc.confidence *= similarity
                            indicators.append(ioc)

            return indicators

        except Exception as e:
            logger.error("Error searching similar indicators", error=str(e))
            return []

    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings"""
        try:
            from difflib import SequenceMatcher

            return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()
        except Exception as e:
            logger.error("Error calculating similarity", error=str(e))
            return 0.0

    async def get_iocs(
        self,
        limit: int = 100,
        offset: int = 0,
        threat_level: Optional[ThreatLevel] = None,
    ) -> List[IOC]:
        """Get IOCs with pagination

        Args:
            limit: Maximum number of IOCs to return
            offset: Number of IOCs to skip
            threat_level: Optional threat level filter

        Returns:
            List of IOCs
        """
        try:
            indicators = []

            # Build query
            query = """
                SELECT id, type, value, description, threat_level, confidence,
                       source, tags, malware_families, kill_chain_phases,
                       created_at, updated_at, expires_at
                FROM indicators
            """
            params = []

            if threat_level:
                query += " WHERE threat_level = ?"
                params.append(threat_level.value)

            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            async with aiosqlite.connect(self.database_path) as db:
                cursor = await db.execute(query, params)

                async for row in cursor:
                    ioc = self._row_to_ioc(row)
                    if ioc:
                        indicators.append(ioc)

            return indicators

        except Exception as e:
            logger.error("Error getting IOCs", error=str(e))
            return []

    async def delete_indicator(self, indicator_id: str) -> bool:
        """Delete indicator by ID

        Args:
            indicator_id: ID of indicator to delete

        Returns:
            True if deleted successfully
        """
        try:
            async with aiosqlite.connect(self.database_path) as db:
                # Get indicator details for cache cleanup
                cursor = await db.execute(
                    """
                    SELECT type, value FROM indicators WHERE id = ?
                """,
                    (indicator_id,),
                )
                row = await cursor.fetchone()

                if not row:
                    return False

                indicator_type, value = row

                # Delete from database
                await db.execute("DELETE FROM indicators WHERE id = ?", (indicator_id,))
                await db.execute(
                    "DELETE FROM matches WHERE indicator_id = ?", (indicator_id,)
                )
                await db.commit()

                # Remove from cache
                if self.redis_client:
                    cache_key = (
                        f"{self.redis_prefixes['indicator']}{indicator_type}:{value}"
                    )
                    await self.redis_client.delete(cache_key)

                # Update statistics
                self.stats["total_indicators"] -= 1
                if indicator_type in self.stats["indicators_by_type"]:
                    self.stats["indicators_by_type"][indicator_type] -= 1
                    if self.stats["indicators_by_type"][indicator_type] <= 0:
                        del self.stats["indicators_by_type"][indicator_type]

                logger.info("Indicator deleted", indicator_id=indicator_id)
                return True

        except Exception as e:
            logger.error(
                "Error deleting indicator", indicator_id=indicator_id, error=str(e)
            )
            return False

    async def cleanup_expired_indicators(self) -> int:
        """Clean up expired indicators

        Returns:
            Number of indicators cleaned up
        """
        try:
            current_time = datetime.utcnow().isoformat()

            async with aiosqlite.connect(self.database_path) as db:
                # Count expired indicators
                cursor = await db.execute(
                    """
                    SELECT COUNT(*) FROM indicators 
                    WHERE expires_at IS NOT NULL AND expires_at <= ?
                """,
                    (current_time,),
                )
                row = await cursor.fetchone()
                expired_count = row[0] if row else 0

                if expired_count > 0:
                    # Delete expired indicators
                    await db.execute(
                        """
                        DELETE FROM indicators 
                        WHERE expires_at IS NOT NULL AND expires_at <= ?
                    """,
                        (current_time,),
                    )

                    # Delete related matches
                    await db.execute("""
                        DELETE FROM matches 
                        WHERE indicator_id NOT IN (SELECT id FROM indicators)
                    """)

                    await db.commit()

                    # Update statistics
                    await self._load_statistics()

                    logger.info("Expired indicators cleaned up", count=expired_count)

                return expired_count

        except Exception as e:
            logger.error("Error cleaning up expired indicators", error=str(e))
            return 0

    async def set_feed_last_update(self, feed_id: str, timestamp: datetime):
        """Set last update timestamp for feed"""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                await db.execute(
                    """
                    INSERT OR REPLACE INTO feeds (id, name, url, feed_type, last_update, updated_at)
                    SELECT COALESCE(f.id, ?), 
                           COALESCE(f.name, 'Unknown'), 
                           COALESCE(f.url, ''), 
                           COALESCE(f.feed_type, 'unknown'),
                           ?,
                           ?
                    FROM (SELECT ? as id) t
                    LEFT JOIN feeds f ON f.id = t.id
                """,
                    (
                        feed_id,
                        timestamp.isoformat(),
                        datetime.utcnow().isoformat(),
                        feed_id,
                    ),
                )

                await db.commit()

        except Exception as e:
            logger.error(
                "Error setting feed last update", feed_id=feed_id, error=str(e)
            )

    async def get_feed_last_update(self, feed_id: str) -> Optional[datetime]:
        """Get last update timestamp for feed"""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                cursor = await db.execute(
                    """
                    SELECT last_update FROM feeds WHERE id = ?
                """,
                    (feed_id,),
                )
                row = await cursor.fetchone()

                if row and row[0]:
                    return datetime.fromisoformat(row[0])

                return None

        except Exception as e:
            logger.error(
                "Error getting feed last update", feed_id=feed_id, error=str(e)
            )
            return None

    async def get_feed_status(self) -> List[Dict[str, Any]]:
        """Get status of all feeds"""
        try:
            feeds = []

            async with aiosqlite.connect(self.database_path) as db:
                cursor = await db.execute("""
                    SELECT id, name, url, feed_type, enabled, last_update, 
                           last_success, last_error, indicator_count
                    FROM feeds
                """)

                async for row in cursor:
                    feeds.append(
                        {
                            "id": row[0],
                            "name": row[1],
                            "url": row[2],
                            "feed_type": row[3],
                            "enabled": bool(row[4]),
                            "last_update": row[5],
                            "last_success": row[6],
                            "last_error": row[7],
                            "indicator_count": row[8] or 0,
                        }
                    )

            return feeds

        except Exception as e:
            logger.error("Error getting feed status", error=str(e))
            return []

    async def record_match(
        self,
        match_id: str,
        indicator_id: str,
        event_id: str,
        matched_value: str,
        field_name: str,
        confidence: float,
    ):
        """Record a threat intelligence match

        Args:
            match_id: Unique match identifier
            indicator_id: ID of matched indicator
            event_id: ID of event that matched
            matched_value: Value that was matched
            field_name: Field where match was found
            confidence: Match confidence score
        """
        try:
            async with aiosqlite.connect(self.database_path) as db:
                await db.execute(
                    """
                    INSERT OR REPLACE INTO matches 
                    (id, indicator_id, event_id, matched_value, field_name, confidence, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        match_id,
                        indicator_id,
                        event_id,
                        matched_value,
                        field_name,
                        confidence,
                        datetime.utcnow().isoformat(),
                    ),
                )

                await db.commit()

        except Exception as e:
            logger.error("Error recording match", match_id=match_id, error=str(e))

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        return {
            **self.stats,
            "database_path": str(self.database_path),
            "redis_available": self.redis_client is not None,
            "cache_ttl": self.cache_ttl,
        }

    async def vacuum_database(self):
        """Vacuum database to reclaim space"""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                await db.execute("VACUUM")
                logger.info("Database vacuumed successfully")

                # Update database size statistic
                self.stats["database_size"] = self.database_path.stat().st_size

        except Exception as e:
            logger.error("Error vacuuming database", error=str(e))

    async def close(self):
        """Close database connections"""
        try:
            # Close any remaining connections in pool
            for conn in self.db_connections:
                if conn:
                    await conn.close()

            self.db_connections.clear()
            logger.info("Threat database closed")

        except Exception as e:
            logger.error("Error closing database", error=str(e))

    # Enhanced database methods for production performance

    async def _create_enhanced_schema(self):
        """Create enhanced database schema with optimizations"""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                # Enable WAL mode for better concurrency
                await db.execute("PRAGMA journal_mode=WAL")
                await db.execute("PRAGMA synchronous=NORMAL")
                await db.execute("PRAGMA cache_size=10000")
                await db.execute("PRAGMA temp_store=memory")
                await db.execute("PRAGMA mmap_size=268435456")  # 256MB

                # Create enhanced indicators table
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS indicators (
                        id TEXT PRIMARY KEY,
                        type TEXT NOT NULL,
                        value TEXT NOT NULL,
                        description TEXT,
                        threat_level TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        source TEXT,
                        tags TEXT,  -- JSON array
                        malware_families TEXT,  -- JSON array
                        kill_chain_phases TEXT,  -- JSON array
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        expires_at TEXT,
                        first_seen TEXT,
                        last_seen TEXT,
                        hit_count INTEGER DEFAULT 0,
                        quality_score REAL DEFAULT 0.5,
                        hash_signature TEXT,  -- For deduplication
                        metadata TEXT  -- JSON for additional data
                    )
                """)

                # Create all other enhanced tables and indexes
                await self._create_enhanced_tables(db)
                await db.commit()

                logger.info("Enhanced database schema created successfully")

        except Exception as e:
            logger.error("Error creating enhanced database schema", error=str(e))
            raise

    async def _create_enhanced_tables(self, db: aiosqlite.Connection):
        """Create all enhanced tables"""
        # Enhanced matches table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS matches (
                id TEXT PRIMARY KEY,
                indicator_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                matched_value TEXT NOT NULL,
                field_name TEXT NOT NULL,
                confidence REAL NOT NULL,
                timestamp TEXT NOT NULL,
                context TEXT,  -- JSON for match context
                FOREIGN KEY (indicator_id) REFERENCES indicators (id)
            )
        """)

        # Create deduplication table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS duplicates (
                id TEXT PRIMARY KEY,
                primary_indicator_id TEXT NOT NULL,
                duplicate_indicator_id TEXT NOT NULL,
                similarity_score REAL NOT NULL,
                merge_timestamp TEXT NOT NULL,
                FOREIGN KEY (primary_indicator_id) REFERENCES indicators (id)
            )
        """)

    async def _create_performance_indexes(self):
        """Create performance-optimized indexes"""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                indexes = [
                    # Core performance indexes
                    "CREATE INDEX IF NOT EXISTS idx_indicators_type_value ON indicators (type, value)",
                    "CREATE INDEX IF NOT EXISTS idx_indicators_threat_confidence ON indicators (threat_level, confidence DESC)",
                    "CREATE INDEX IF NOT EXISTS idx_indicators_source_created ON indicators (source, created_at DESC)",
                    "CREATE INDEX IF NOT EXISTS idx_indicators_hit_count ON indicators (hit_count DESC)",
                    "CREATE INDEX IF NOT EXISTS idx_indicators_quality_score ON indicators (quality_score DESC)",
                    "CREATE INDEX IF NOT EXISTS idx_indicators_hash_signature ON indicators (hash_signature)",
                    "CREATE INDEX IF NOT EXISTS idx_matches_indicator_timestamp ON matches (indicator_id, timestamp DESC)",
                    "CREATE INDEX IF NOT EXISTS idx_duplicates_primary ON duplicates (primary_indicator_id)",
                ]

                for index_sql in indexes:
                    await db.execute(index_sql)

                await db.commit()
                logger.info("Performance indexes created", count=len(indexes))

        except Exception as e:
            logger.error("Error creating performance indexes", error=str(e))

    async def _start_background_tasks(self):
        """Start background optimization tasks"""
        try:
            # Start batch processor
            if not self.batch_processor_running:
                self._batch_processor_task = asyncio.create_task(
                    self._batch_processor()
                )
                self.batch_processor_running = True

            # Start cleanup task
            self._cleanup_task = asyncio.create_task(self._background_cleanup())

            logger.info("Background tasks started successfully")

        except Exception as e:
            logger.error("Error starting background tasks", error=str(e))

    async def _analyze_database(self):
        """Analyze database for optimization opportunities"""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                # Analyze table statistics
                await db.execute("ANALYZE")

                # Update database size statistic
                self.stats["database_size"] = self.database_path.stat().st_size

                logger.info("Database analysis completed")

        except Exception as e:
            logger.error("Error analyzing database", error=str(e))

    async def _batch_processor(self):
        """Process indicators in batches for better performance"""
        try:
            while self.batch_processor_running:
                try:
                    await asyncio.sleep(10)  # Process every 10 seconds

                    # This would implement actual batch processing logic
                    # For now, just maintain the structure

                except Exception as e:
                    logger.error("Error in batch processor", error=str(e))
                    await asyncio.sleep(1)

        except asyncio.CancelledError:
            logger.info("Batch processor stopped")

    async def _background_cleanup(self):
        """Background cleanup of expired indicators"""
        try:
            while True:
                await asyncio.sleep(3600)  # Run every hour

                try:
                    expired_count = await self.cleanup_expired_indicators()
                    if expired_count > 0:
                        logger.info(
                            "Background cleanup completed", expired_count=expired_count
                        )

                except Exception as e:
                    logger.error("Error in background cleanup", error=str(e))

        except asyncio.CancelledError:
            logger.info("Background cleanup task cancelled")

    async def get_enhanced_statistics(self) -> Dict[str, Any]:
        """Get enhanced database statistics including performance metrics"""
        stats = self.get_statistics()

        # Add cache statistics
        cache_stats = self.cache.get_stats()
        stats["cache_performance"] = cache_stats

        # Add query performance metrics
        if self.query_times:
            stats["query_performance"]["avg_query_time"] = sum(self.query_times) / len(
                self.query_times
            )
            stats["query_performance"]["max_query_time"] = max(self.query_times)
            stats["query_performance"]["min_query_time"] = min(self.query_times)

        return stats

    async def optimize_database(self) -> Dict[str, Any]:
        """Manually trigger database optimization"""
        try:
            start_time = time.time()

            # Cleanup expired indicators
            expired_count = await self.cleanup_expired_indicators()

            # Vacuum database
            await self.vacuum_database()

            # Recreate indexes
            await self._create_performance_indexes()

            # Analyze database
            await self._analyze_database()

            optimization_time = time.time() - start_time

            result = {
                "success": True,
                "expired_indicators_removed": expired_count,
                "optimization_time_seconds": optimization_time,
                "database_size_mb": self.stats.get("database_size", 0) / (1024 * 1024),
            }

            logger.info("Manual database optimization completed", **result)
            return result

        except Exception as e:
            logger.error("Error in manual database optimization", error=str(e))
            return {"success": False, "error": str(e)}
