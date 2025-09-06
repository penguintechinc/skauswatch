"""
Async Database Operations for SkausWatch Manager Service

Provides optimized async database operations with connection pooling,
caching, batch operations, and performance monitoring.
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import uuid4

import asyncpg
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from ...shared.performance import (
    ConnectionPoolManager, PoolConfig, HealthCheckConfig,
    CacheManager, CacheConfig, cache_decorator,
    async_retry, async_timeout, async_batch_processor
)

logger = logging.getLogger(__name__)


@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: str
    pool_min_size: int = 5
    pool_max_size: int = 20
    pool_timeout: float = 30.0
    command_timeout: float = 60.0
    enable_caching: bool = True
    cache_ttl: float = 300.0
    batch_size: int = 100
    enable_metrics: bool = True


class AsyncDatabaseManager:
    """Async database manager with performance optimizations"""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.engine = None
        self.session_factory = None
        self.pool_manager = None
        self.cache_manager = None
        self.metrics = {
            'queries_executed': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'avg_query_time': 0.0,
            'slow_queries': 0,
            'batch_operations': 0
        }
        
    async def initialize(self):
        """Initialize database connections and caching"""
        # Create async engine
        self.engine = create_async_engine(
            self.config.url,
            pool_size=self.config.pool_min_size,
            max_overflow=self.config.pool_max_size - self.config.pool_min_size,
            pool_timeout=self.config.pool_timeout,
            pool_pre_ping=True,
            echo=False  # Set to True for query logging
        )
        
        # Create session factory
        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Initialize connection pool manager
        self.pool_manager = ConnectionPoolManager()
        
        pool_config = PoolConfig(
            min_size=self.config.pool_min_size,
            max_size=self.config.pool_max_size,
            connection_timeout=self.config.pool_timeout,
            query_timeout=self.config.command_timeout,
            auto_scale=True,
            metrics_enabled=self.config.enable_metrics
        )
        
        health_config = HealthCheckConfig(
            enabled=True,
            interval=30.0,
            timeout=5.0,
            query="SELECT 1"
        )
        
        await self.pool_manager.create_database_pool(
            "manager_db",
            self.config.url,
            pool_config,
            health_config
        )
        
        await self.pool_manager.start_all_pools()
        
        # Initialize caching
        if self.config.enable_caching:
            self.cache_manager = CacheManager()
            cache_config = CacheConfig(
                max_size=1000,
                default_ttl=self.config.cache_ttl,
                metrics_enabled=True
            )
            self.cache_manager.create_memory_cache("db_cache", cache_config)
            
        logger.info("Async database manager initialized")
        
    async def close(self):
        """Close database connections"""
        if self.pool_manager:
            await self.pool_manager.stop_all_pools()
        if self.cache_manager:
            await self.cache_manager.close_all()
        if self.engine:
            await self.engine.dispose()
            
    @asynccontextmanager
    async def get_session(self):
        """Get async database session"""
        async with self.session_factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
                
    async def get_connection(self):
        """Get database connection from pool"""
        pool = self.pool_manager.get_pool("manager_db")
        return await pool.acquire()
        
    @async_retry(max_attempts=3, delay=1.0)
    @async_timeout(60.0)
    async def execute_query(self, 
                           query: str, 
                           params: Optional[Dict[str, Any]] = None,
                           fetch: str = "all",
                           cache_key: Optional[str] = None,
                           cache_ttl: Optional[float] = None) -> Any:
        """Execute query with retry and caching"""
        start_time = time.time()
        
        # Check cache first
        if cache_key and self.cache_manager:
            cache = self.cache_manager.get_cache("db_cache")
            cached_result = await cache.get(cache_key)
            if cached_result is not None:
                self.metrics['cache_hits'] += 1
                return cached_result
            self.metrics['cache_misses'] += 1
            
        async with self.get_session() as session:
            try:
                result = await session.execute(text(query), params or {})
                
                if fetch == "all":
                    data = result.fetchall()
                elif fetch == "one":
                    data = result.fetchone()
                elif fetch == "scalar":
                    data = result.scalar()
                else:  # "none"
                    data = None
                    
                await session.commit()
                
                # Cache result if requested
                if cache_key and data is not None and self.cache_manager:
                    cache = self.cache_manager.get_cache("db_cache")
                    await cache.set(cache_key, data, cache_ttl or self.config.cache_ttl)
                    
                # Update metrics
                query_time = time.time() - start_time
                self.metrics['queries_executed'] += 1
                
                if self.metrics['avg_query_time'] == 0:
                    self.metrics['avg_query_time'] = query_time
                else:
                    self.metrics['avg_query_time'] = (
                        self.metrics['avg_query_time'] * 0.95 + query_time * 0.05
                    )
                    
                if query_time > 1.0:  # Slow query threshold
                    self.metrics['slow_queries'] += 1
                    logger.warning(f"Slow query detected: {query_time:.2f}s - {query[:100]}")
                    
                return data
                
            except Exception as e:
                logger.error(f"Query execution failed: {e}")
                raise
                
    async def execute_batch(self, 
                           operations: List[Tuple[str, Dict[str, Any]]],
                           batch_size: Optional[int] = None) -> List[Any]:
        """Execute batch operations efficiently"""
        batch_size = batch_size or self.config.batch_size
        results = []
        
        async with self.get_session() as session:
            try:
                # Process operations in batches
                for i in range(0, len(operations), batch_size):
                    batch = operations[i:i + batch_size]
                    batch_results = []
                    
                    for query, params in batch:
                        result = await session.execute(text(query), params)
                        batch_results.append(result.fetchall())
                        
                    results.extend(batch_results)
                    
                await session.commit()
                self.metrics['batch_operations'] += 1
                
                return results
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Batch execution failed: {e}")
                raise
                
    async def bulk_insert(self, 
                         table: str, 
                         data: List[Dict[str, Any]],
                         batch_size: Optional[int] = None,
                         on_conflict: str = "IGNORE") -> int:
        """Bulk insert with conflict handling"""
        if not data:
            return 0
            
        batch_size = batch_size or self.config.batch_size
        total_inserted = 0
        
        async with self.get_session() as session:
            try:
                # Process data in batches
                for i in range(0, len(data), batch_size):
                    batch = data[i:i + batch_size]
                    
                    if batch:
                        # Build columns and values
                        columns = list(batch[0].keys())
                        placeholders = ", ".join([f":{col}" for col in columns])
                        
                        if on_conflict.upper() == "IGNORE":
                            query = f"""
                            INSERT INTO {table} ({', '.join(columns)})
                            VALUES ({placeholders})
                            ON CONFLICT DO NOTHING
                            """
                        else:
                            query = f"""
                            INSERT INTO {table} ({', '.join(columns)})
                            VALUES ({placeholders})
                            """
                            
                        for row in batch:
                            result = await session.execute(text(query), row)
                            total_inserted += result.rowcount
                            
                await session.commit()
                logger.info(f"Bulk inserted {total_inserted} rows into {table}")
                return total_inserted
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Bulk insert failed: {e}")
                raise
                
    async def bulk_update(self, 
                         table: str, 
                         data: List[Dict[str, Any]],
                         key_column: str,
                         batch_size: Optional[int] = None) -> int:
        """Bulk update operations"""
        if not data:
            return 0
            
        batch_size = batch_size or self.config.batch_size
        total_updated = 0
        
        async with self.get_session() as session:
            try:
                # Process data in batches
                for i in range(0, len(data), batch_size):
                    batch = data[i:i + batch_size]
                    
                    for row in batch:
                        if key_column not in row:
                            continue
                            
                        key_value = row[key_column]
                        update_data = {k: v for k, v in row.items() if k != key_column}
                        
                        if update_data:
                            set_clause = ", ".join([f"{col} = :{col}" for col in update_data.keys()])
                            query = f"""
                            UPDATE {table}
                            SET {set_clause}
                            WHERE {key_column} = :key_value
                            """
                            
                            params = {**update_data, 'key_value': key_value}
                            result = await session.execute(text(query), params)
                            total_updated += result.rowcount
                            
                await session.commit()
                logger.info(f"Bulk updated {total_updated} rows in {table}")
                return total_updated
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Bulk update failed: {e}")
                raise
                
    @cache_decorator(cache_name="db_cache", ttl=300.0)
    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID with caching"""
        query = "SELECT * FROM users WHERE id = :user_id"
        result = await self.execute_query(
            query, 
            {"user_id": user_id}, 
            fetch="one",
            cache_key=f"user:{user_id}"
        )
        return dict(result._mapping) if result else None
        
    @cache_decorator(cache_name="db_cache", ttl=600.0)
    async def get_user_permissions(self, user_id: str) -> List[str]:
        """Get user permissions with caching"""
        query = """
        SELECT DISTINCT p.name
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        JOIN user_roles ur ON rp.role_id = ur.role_id
        WHERE ur.user_id = :user_id
        """
        result = await self.execute_query(
            query,
            {"user_id": user_id},
            cache_key=f"permissions:{user_id}"
        )
        return [row[0] for row in result] if result else []
        
    async def get_pending_approvals(self, 
                                  user_id: Optional[str] = None,
                                  limit: int = 100) -> List[Dict[str, Any]]:
        """Get pending approvals for user"""
        if user_id:
            query = """
            SELECT a.*, r.type as request_type, r.metadata
            FROM approvals a
            JOIN requests r ON a.request_id = r.id
            WHERE a.status = 'pending'
            AND (a.assigned_to = :user_id OR a.assigned_to IS NULL)
            ORDER BY a.created_at DESC
            LIMIT :limit
            """
            params = {"user_id": user_id, "limit": limit}
        else:
            query = """
            SELECT a.*, r.type as request_type, r.metadata
            FROM approvals a
            JOIN requests r ON a.request_id = r.id
            WHERE a.status = 'pending'
            ORDER BY a.created_at DESC
            LIMIT :limit
            """
            params = {"limit": limit}
            
        result = await self.execute_query(query, params)
        return [dict(row._mapping) for row in result] if result else []
        
    async def update_approval_status(self, 
                                   approval_id: str, 
                                   status: str, 
                                   user_id: str,
                                   comment: Optional[str] = None) -> bool:
        """Update approval status"""
        query = """
        UPDATE approvals 
        SET status = :status, 
            updated_at = NOW(),
            updated_by = :user_id,
            comment = COALESCE(:comment, comment)
        WHERE id = :approval_id
        """
        
        params = {
            "approval_id": approval_id,
            "status": status,
            "user_id": user_id,
            "comment": comment
        }
        
        result = await self.execute_query(query, params, fetch="none")
        
        # Invalidate cache for affected user
        if self.cache_manager:
            cache = self.cache_manager.get_cache("db_cache")
            await cache.delete(f"pending_approvals:{user_id}")
            
        return True
        
    async def get_audit_logs(self,
                           user_id: Optional[str] = None,
                           action: Optional[str] = None,
                           start_time: Optional[str] = None,
                           end_time: Optional[str] = None,
                           limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit logs with filters"""
        conditions = ["1=1"]
        params = {"limit": limit}
        
        if user_id:
            conditions.append("user_id = :user_id")
            params["user_id"] = user_id
            
        if action:
            conditions.append("action = :action")
            params["action"] = action
            
        if start_time:
            conditions.append("created_at >= :start_time")
            params["start_time"] = start_time
            
        if end_time:
            conditions.append("created_at <= :end_time")
            params["end_time"] = end_time
            
        query = f"""
        SELECT * FROM audit_logs
        WHERE {" AND ".join(conditions)}
        ORDER BY created_at DESC
        LIMIT :limit
        """
        
        result = await self.execute_query(query, params)
        return [dict(row._mapping) for row in result] if result else []
        
    async def log_audit_event(self, 
                            user_id: str,
                            action: str,
                            resource_type: str,
                            resource_id: Optional[str] = None,
                            details: Optional[Dict[str, Any]] = None,
                            ip_address: Optional[str] = None) -> str:
        """Log audit event"""
        event_id = str(uuid4())
        
        query = """
        INSERT INTO audit_logs (
            id, user_id, action, resource_type, resource_id,
            details, ip_address, created_at
        ) VALUES (
            :id, :user_id, :action, :resource_type, :resource_id,
            :details, :ip_address, NOW()
        )
        """
        
        import json
        params = {
            "id": event_id,
            "user_id": user_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": json.dumps(details) if details else None,
            "ip_address": ip_address
        }
        
        await self.execute_query(query, params, fetch="none")
        return event_id
        
    async def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        stats = {}
        
        # User statistics
        user_stats = await self.execute_query(
            "SELECT COUNT(*) as total_users FROM users",
            fetch="one"
        )
        stats["total_users"] = user_stats[0] if user_stats else 0
        
        # Active approvals
        approval_stats = await self.execute_query(
            "SELECT COUNT(*) as pending_approvals FROM approvals WHERE status = 'pending'",
            fetch="one"
        )
        stats["pending_approvals"] = approval_stats[0] if approval_stats else 0
        
        # Recent audit events
        audit_stats = await self.execute_query(
            "SELECT COUNT(*) as recent_events FROM audit_logs WHERE created_at > NOW() - INTERVAL '24 hours'",
            fetch="one"
        )
        stats["recent_audit_events"] = audit_stats[0] if audit_stats else 0
        
        # Add internal metrics
        stats.update(self.metrics)
        
        # Add pool metrics
        if self.pool_manager:
            pool_metrics = self.pool_manager.get_all_metrics()
            stats["connection_pool"] = pool_metrics.get("manager_db", {})
            
        # Add cache metrics
        if self.cache_manager:
            cache_metrics = self.cache_manager.get_all_stats()
            stats["cache"] = cache_metrics.get("db_cache", {})
            
        return stats
        
    async def health_check(self) -> Dict[str, Any]:
        """Perform database health check"""
        try:
            start_time = time.time()
            await self.execute_query("SELECT 1", fetch="scalar")
            response_time = time.time() - start_time
            
            return {
                "status": "healthy",
                "response_time": response_time,
                "pool_status": "active" if self.pool_manager else "inactive",
                "cache_status": "active" if self.cache_manager else "inactive"
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "pool_status": "error",
                "cache_status": "unknown"
            }
            
    async def optimize_tables(self) -> Dict[str, Any]:
        """Optimize database tables"""
        optimization_results = {}
        
        # Get table sizes
        size_query = """
        SELECT schemaname, tablename, pg_total_relation_size(schemaname||'.'||tablename) as size
        FROM pg_tables 
        WHERE schemaname NOT IN ('information_schema', 'pg_catalog')
        ORDER BY size DESC
        """
        
        try:
            table_sizes = await self.execute_query(size_query)
            optimization_results["table_sizes"] = [
                {"schema": row[0], "table": row[1], "size_bytes": row[2]}
                for row in table_sizes
            ]
            
            # Vacuum and analyze large tables
            for row in table_sizes[:5]:  # Top 5 largest tables
                table_name = f"{row[0]}.{row[1]}"
                try:
                    await self.execute_query(f"VACUUM ANALYZE {table_name}", fetch="none")
                    optimization_results[f"optimized_{table_name}"] = "success"
                except Exception as e:
                    optimization_results[f"optimized_{table_name}"] = f"error: {str(e)}"
                    
        except Exception as e:
            optimization_results["error"] = str(e)
            
        return optimization_results


# Background task processor for async operations
class AsyncBackgroundProcessor:
    """Background processor for async database operations"""
    
    def __init__(self, db_manager: AsyncDatabaseManager):
        self.db_manager = db_manager
        self.task_queue = asyncio.Queue()
        self.workers: List[asyncio.Task] = []
        self.running = False
        
    async def start(self, num_workers: int = 3):
        """Start background workers"""
        self.running = True
        
        for i in range(num_workers):
            worker = asyncio.create_task(self._worker(f"worker-{i}"))
            self.workers.append(worker)
            
        logger.info(f"Started {num_workers} background workers")
        
    async def stop(self):
        """Stop background workers"""
        self.running = False
        
        # Cancel all workers
        for worker in self.workers:
            worker.cancel()
            
        # Wait for workers to finish
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
        
    async def submit_task(self, task_type: str, **kwargs):
        """Submit background task"""
        task_id = str(uuid4())
        task = {
            "id": task_id,
            "type": task_type,
            "params": kwargs,
            "submitted_at": time.time()
        }
        
        await self.task_queue.put(task)
        return task_id
        
    async def _worker(self, worker_name: str):
        """Background worker"""
        logger.info(f"Background worker {worker_name} started")
        
        while self.running:
            try:
                # Get task with timeout
                task = await asyncio.wait_for(
                    self.task_queue.get(), 
                    timeout=1.0
                )
                
                await self._process_task(task, worker_name)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Worker {worker_name} error: {e}")
                
        logger.info(f"Background worker {worker_name} stopped")
        
    async def _process_task(self, task: Dict[str, Any], worker_name: str):
        """Process background task"""
        task_type = task["type"]
        task_id = task["id"]
        params = task["params"]
        
        try:
            if task_type == "cleanup_audit_logs":
                await self._cleanup_audit_logs(**params)
            elif task_type == "update_user_stats":
                await self._update_user_stats(**params)
            elif task_type == "send_notification":
                await self._send_notification(**params)
            else:
                logger.warning(f"Unknown task type: {task_type}")
                
        except Exception as e:
            logger.error(f"Task {task_id} failed in {worker_name}: {e}")
            
    async def _cleanup_audit_logs(self, days_to_keep: int = 90):
        """Clean up old audit logs"""
        query = "DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL ':days days'"
        result = await self.db_manager.execute_query(
            query, 
            {"days": days_to_keep}, 
            fetch="none"
        )
        logger.info(f"Cleaned up old audit logs (keeping {days_to_keep} days)")
        
    async def _update_user_stats(self, user_id: str):
        """Update user statistics"""
        # This would update user activity statistics
        query = """
        UPDATE users 
        SET last_activity = NOW(),
            login_count = login_count + 1
        WHERE id = :user_id
        """
        await self.db_manager.execute_query(query, {"user_id": user_id}, fetch="none")
        
    async def _send_notification(self, user_id: str, message: str, notification_type: str = "info"):
        """Send notification (placeholder)"""
        # This would integrate with notification system
        logger.info(f"Notification for {user_id}: {message} ({notification_type})")