"""
SkausWatch AAA Monitor Service - Database Collector

Database collector for retrieving logs stored in databases.
Supports multiple database types and custom SQL queries.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, AsyncGenerator
import traceback

import structlog
import aiopg
import aiomysql
import aiosqlite

from ..models import (
    BaseEvent,
    AuthenticationEvent,
    AuthorizationEvent,
    SystemCallEvent,
    ProcessEvent,
    NetworkEvent,
    FileAccessEvent,
    EventType,
    LogSource,
    Severity,
)

logger = structlog.get_logger(__name__)


class DatabaseCollector:
    """Database collector for logs stored in databases"""

    def __init__(self, config: Dict[str, Any], log_processor, analysis_engine):
        """Initialize Database collector

        Args:
            config: Database collector configuration
            log_processor: Log processor instance
            analysis_engine: Analysis engine instance
        """
        self.config = config
        self.log_processor = log_processor
        self.analysis_engine = analysis_engine

        # Collection state
        self.running = False
        self.collection_tasks = []

        # Database connections
        self.db_pools = {}

        # Query tracking (for incremental collection)
        self.query_cursors = {}

    async def initialize(self):
        """Initialize database collector"""
        try:
            # Initialize database connections
            for connection_config in self.config.connections:
                await self._initialize_connection(connection_config)

            logger.info(
                "Database collector initialized successfully",
                connections=len(self.config.connections),
                queries=len(self.config.queries),
            )

        except Exception as e:
            logger.error("Failed to initialize database collector", error=str(e))
            raise

    async def _initialize_connection(self, connection_config: Dict):
        """Initialize database connection"""
        try:
            conn_id = connection_config["id"]
            db_type = connection_config["type"].lower()

            if db_type == "postgresql":
                await self._initialize_postgresql(conn_id, connection_config)
            elif db_type == "mysql":
                await self._initialize_mysql(conn_id, connection_config)
            elif db_type == "sqlite":
                await self._initialize_sqlite(conn_id, connection_config)
            else:
                logger.error("Unsupported database type", type=db_type)

        except Exception as e:
            logger.error(
                "Failed to initialize database connection",
                connection_id=conn_id,
                error=str(e),
            )

    async def _initialize_postgresql(self, conn_id: str, config: Dict):
        """Initialize PostgreSQL connection"""
        try:
            dsn = (
                f"host={config['host']} port={config.get('port', 5432)} "
                f"dbname={config['database']} user={config['username']} "
                f"password={config['password']}"
            )

            pool = await aiopg.create_pool(
                dsn,
                minsize=1,
                maxsize=config.get("max_connections", 5),
                timeout=config.get("timeout", 30),
            )

            self.db_pools[conn_id] = {
                "type": "postgresql",
                "pool": pool,
                "config": config,
            }

            logger.info("PostgreSQL connection initialized", connection_id=conn_id)

        except Exception as e:
            logger.error(
                "Failed to initialize PostgreSQL connection",
                connection_id=conn_id,
                error=str(e),
            )

    async def _initialize_mysql(self, conn_id: str, config: Dict):
        """Initialize MySQL connection"""
        try:
            pool = await aiomysql.create_pool(
                host=config["host"],
                port=config.get("port", 3306),
                user=config["username"],
                password=config["password"],
                db=config["database"],
                minsize=1,
                maxsize=config.get("max_connections", 5),
                autocommit=True,
            )

            self.db_pools[conn_id] = {"type": "mysql", "pool": pool, "config": config}

            logger.info("MySQL connection initialized", connection_id=conn_id)

        except Exception as e:
            logger.error(
                "Failed to initialize MySQL connection",
                connection_id=conn_id,
                error=str(e),
            )

    async def _initialize_sqlite(self, conn_id: str, config: Dict):
        """Initialize SQLite connection"""
        try:
            # SQLite doesn't use connection pools in the same way
            self.db_pools[conn_id] = {
                "type": "sqlite",
                "database": config["database"],
                "config": config,
            }

            # Test connection
            async with aiosqlite.connect(config["database"]) as db:
                await db.execute("SELECT 1")

            logger.info("SQLite connection initialized", connection_id=conn_id)

        except Exception as e:
            logger.error(
                "Failed to initialize SQLite connection",
                connection_id=conn_id,
                error=str(e),
            )

    async def start_collection(self):
        """Start database log collection"""
        if self.running:
            logger.warning("Database collector already running")
            return

        self.running = True
        logger.info("Starting database log collection")

        try:
            # Start query execution for each configured query
            for query_config in self.config.queries:
                task = asyncio.create_task(self._execute_query_loop(query_config))
                self.collection_tasks.append(task)

            # Wait for all tasks
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)

        except Exception as e:
            logger.error("Error in database log collection", error=str(e))
        finally:
            self.running = False

    async def stop(self):
        """Stop database log collection"""
        self.running = False

        # Cancel all collection tasks
        for task in self.collection_tasks:
            if not task.done():
                task.cancel()

        # Wait for tasks to complete
        if self.collection_tasks:
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)

        self.collection_tasks.clear()

        # Close database connections
        for conn_id, db_info in self.db_pools.items():
            try:
                if db_info["type"] in ["postgresql", "mysql"]:
                    db_info["pool"].close()
                    await db_info["pool"].wait_closed()
            except Exception as e:
                logger.error(
                    "Error closing database connection",
                    connection_id=conn_id,
                    error=str(e),
                )

        self.db_pools.clear()

        logger.info("Database collector stopped")

    async def _execute_query_loop(self, query_config: Dict):
        """Execute query in a loop"""
        query_id = query_config["id"]

        logger.info("Starting query execution loop", query_id=query_id)

        try:
            while self.running:
                try:
                    await self._execute_query(query_config)
                    await asyncio.sleep(self.config.poll_interval)

                except Exception as e:
                    logger.error(
                        "Error executing query", query_id=query_id, error=str(e)
                    )
                    await asyncio.sleep(60)

        except asyncio.CancelledError:
            logger.info("Query execution cancelled", query_id=query_id)
        except Exception as e:
            logger.error(
                "Fatal error in query execution", query_id=query_id, error=str(e)
            )

    async def _execute_query(self, query_config: Dict):
        """Execute database query and process results"""
        try:
            query_id = query_config["id"]
            connection_id = query_config["connection_id"]
            sql = query_config["sql"]

            # Get database connection
            if connection_id not in self.db_pools:
                logger.error(
                    "Database connection not found", connection_id=connection_id
                )
                return

            db_info = self.db_pools[connection_id]

            # Add time-based filtering for incremental collection
            if query_config.get("incremental", True):
                sql = await self._add_time_filter(sql, query_id)

            # Execute query based on database type
            if db_info["type"] == "postgresql":
                rows = await self._execute_postgresql_query(db_info, sql, query_config)
            elif db_info["type"] == "mysql":
                rows = await self._execute_mysql_query(db_info, sql, query_config)
            elif db_info["type"] == "sqlite":
                rows = await self._execute_sqlite_query(db_info, sql, query_config)
            else:
                logger.error("Unsupported database type", type=db_info["type"])
                return

            # Process results
            if rows:
                await self._process_query_results(rows, query_config)
                logger.debug(
                    "Processed query results", query_id=query_id, rows=len(rows)
                )

        except Exception as e:
            logger.error(
                "Error executing query", query_id=query_config["id"], error=str(e)
            )

    async def _add_time_filter(self, sql: str, query_id: str) -> str:
        """Add time-based filter for incremental collection"""
        try:
            # Get last execution time or use poll interval
            last_time = self.query_cursors.get(
                query_id,
                datetime.utcnow() - timedelta(seconds=self.config.poll_interval),
            )

            # Update cursor
            self.query_cursors[query_id] = datetime.utcnow()

            # Add WHERE clause if not present, or extend existing WHERE
            time_filter = f"timestamp >= '{last_time.isoformat()}'"

            if " WHERE " in sql.upper():
                sql += f" AND {time_filter}"
            else:
                sql += f" WHERE {time_filter}"

            return sql

        except Exception as e:
            logger.error("Error adding time filter", query_id=query_id, error=str(e))
            return sql

    async def _execute_postgresql_query(
        self, db_info: Dict, sql: str, query_config: Dict
    ) -> List[Dict]:
        """Execute PostgreSQL query"""
        try:
            async with db_info["pool"].acquire() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(sql)
                    columns = [desc[0] for desc in cur.description]
                    rows = await cur.fetchall()

                    return [dict(zip(columns, row)) for row in rows]

        except Exception as e:
            logger.error("Error executing PostgreSQL query", error=str(e))
            return []

    async def _execute_mysql_query(
        self, db_info: Dict, sql: str, query_config: Dict
    ) -> List[Dict]:
        """Execute MySQL query"""
        try:
            async with db_info["pool"].acquire() as conn:
                async with conn.cursor(aiomysql.DictCursor) as cur:
                    await cur.execute(sql)
                    rows = await cur.fetchall()
                    return rows

        except Exception as e:
            logger.error("Error executing MySQL query", error=str(e))
            return []

    async def _execute_sqlite_query(
        self, db_info: Dict, sql: str, query_config: Dict
    ) -> List[Dict]:
        """Execute SQLite query"""
        try:
            async with aiosqlite.connect(db_info["database"]) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(sql) as cur:
                    rows = await cur.fetchall()
                    return [dict(row) for row in rows]

        except Exception as e:
            logger.error("Error executing SQLite query", error=str(e))
            return []

    async def _process_query_results(self, rows: List[Dict], query_config: Dict):
        """Process query results and create events"""
        try:
            for row in rows:
                # Create event from database row
                event = await self._create_event_from_row(row, query_config)
                if event:
                    await self.log_processor.process_event(event)

        except Exception as e:
            logger.error("Error processing query results", error=str(e))

    async def _create_event_from_row(
        self, row: Dict, query_config: Dict
    ) -> Optional[BaseEvent]:
        """Create event from database row"""
        try:
            # Extract standard fields
            timestamp_field = query_config.get("timestamp_field", "timestamp")
            message_field = query_config.get("message_field", "message")
            severity_field = query_config.get("severity_field", "severity")

            # Parse timestamp
            try:
                timestamp_val = row.get(timestamp_field)
                if isinstance(timestamp_val, str):
                    timestamp = datetime.fromisoformat(
                        timestamp_val.replace("Z", "+00:00")
                    )
                elif isinstance(timestamp_val, datetime):
                    timestamp = timestamp_val
                else:
                    timestamp = datetime.utcnow()
            except Exception:
                timestamp = datetime.utcnow()

            # Extract message
            message = str(row.get(message_field, ""))

            # Map severity
            severity_val = str(row.get(severity_field, "info")).lower()
            severity_map = {
                "critical": Severity.CRITICAL,
                "error": Severity.HIGH,
                "warning": Severity.MEDIUM,
                "warn": Severity.MEDIUM,
                "info": Severity.INFO,
                "debug": Severity.LOW,
            }
            severity = severity_map.get(severity_val, Severity.INFO)

            # Determine event type based on configuration or message content
            event_type = await self._determine_event_type(row, query_config, message)

            # Create specific event types
            if event_type == EventType.AUTHENTICATION:
                return await self._create_auth_event_from_row(
                    row, query_config, timestamp, severity
                )

            # Create generic event
            return BaseEvent(
                source=LogSource.SYSTEM,
                event_type=event_type,
                severity=severity,
                message=message,
                timestamp=timestamp,
                raw_data={
                    "database_row": row,
                    "query_id": query_config["id"],
                    "connection_id": query_config["connection_id"],
                },
                tags=[
                    "database",
                    query_config["id"],
                    query_config.get("category", "generic"),
                ],
            )

        except Exception as e:
            logger.error("Error creating event from row", error=str(e))
            return None

    async def _determine_event_type(
        self, row: Dict, query_config: Dict, message: str
    ) -> EventType:
        """Determine event type from row data"""
        try:
            # Check if event type is specified in configuration
            if "event_type" in query_config:
                type_mapping = {
                    "authentication": EventType.AUTHENTICATION,
                    "authorization": EventType.AUTHORIZATION,
                    "network": EventType.NETWORK,
                    "process": EventType.PROCESS,
                    "file_access": EventType.FILE_ACCESS,
                    "system_call": EventType.SYSTEM_CALL,
                    "security_violation": EventType.SECURITY_VIOLATION,
                    "privilege_escalation": EventType.PRIVILEGE_ESCALATION,
                    "container_event": EventType.CONTAINER_EVENT,
                    "accounting": EventType.ACCOUNTING,
                }
                return type_mapping.get(
                    query_config["event_type"], EventType.ACCOUNTING
                )

            # Infer from message content
            message_lower = message.lower()

            if any(
                keyword in message_lower
                for keyword in ["login", "authentication", "password", "auth"]
            ):
                return EventType.AUTHENTICATION
            elif any(
                keyword in message_lower
                for keyword in ["permission", "access", "denied", "authorized"]
            ):
                return EventType.AUTHORIZATION
            elif any(
                keyword in message_lower
                for keyword in ["network", "connection", "tcp", "udp"]
            ):
                return EventType.NETWORK
            elif any(
                keyword in message_lower
                for keyword in ["process", "started", "stopped", "killed"]
            ):
                return EventType.PROCESS
            elif any(
                keyword in message_lower
                for keyword in ["file", "read", "write", "create", "delete"]
            ):
                return EventType.FILE_ACCESS
            elif any(
                keyword in message_lower
                for keyword in ["security", "violation", "intrusion", "attack"]
            ):
                return EventType.SECURITY_VIOLATION
            elif any(
                keyword in message_lower
                for keyword in ["sudo", "su", "privilege", "escalation"]
            ):
                return EventType.PRIVILEGE_ESCALATION
            else:
                return EventType.ACCOUNTING

        except Exception as e:
            logger.error("Error determining event type", error=str(e))
            return EventType.ACCOUNTING

    async def _create_auth_event_from_row(
        self, row: Dict, query_config: Dict, timestamp: datetime, severity: Severity
    ) -> Optional[AuthenticationEvent]:
        """Create authentication event from database row"""
        try:
            # Extract authentication-specific fields
            username = row.get("username") or row.get("user") or row.get("account")
            source_ip = (
                row.get("source_ip") or row.get("ip_address") or row.get("client_ip")
            )
            success = row.get("success", True)
            method = row.get("method") or row.get("auth_method", "system")
            message = str(row.get(query_config.get("message_field", "message"), ""))

            # Parse success from string if needed
            if isinstance(success, str):
                success = success.lower() in ["true", "success", "yes", "1"]

            return AuthenticationEvent(
                source=LogSource.SYSTEM,
                event_type=EventType.AUTHENTICATION,
                severity=Severity.HIGH if not success else severity,
                message=message,
                timestamp=timestamp,
                username=str(username) if username else None,
                source_ip=str(source_ip) if source_ip else None,
                success=bool(success),
                method=str(method) if method else None,
                raw_data={
                    "database_row": row,
                    "query_id": query_config["id"],
                    "connection_id": query_config["connection_id"],
                },
                tags=["database", "authentication", query_config["id"]],
            )

        except Exception as e:
            logger.error("Error creating auth event from row", error=str(e))
            return None
