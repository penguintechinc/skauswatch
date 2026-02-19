"""
SkausWatch AAA Monitor Service - Buffer Manager

Event buffering and batching service that manages event queues,
implements backpressure control, and provides efficient batch processing.
"""

import asyncio
import json
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
import time
import gzip
import tempfile

import structlog
import redis.asyncio as redis

from .models import BaseEvent, LogSource, EventType, Severity

logger = structlog.get_logger(__name__)


class BufferManager:
    """Event buffer manager for efficient batch processing"""

    def __init__(
        self, config: Dict[str, Any], redis_client: Optional[redis.Redis] = None
    ):
        """Initialize buffer manager

        Args:
            config: Buffer configuration
            redis_client: Optional Redis client for persistent buffering
        """
        self.config = config
        self.redis_client = redis_client

        # In-memory buffers
        self.event_buffers = defaultdict(deque)
        self.buffer_locks = defaultdict(asyncio.Lock)

        # Buffer configuration
        self.max_buffer_size = config.get("max_buffer_size", 1000)
        self.flush_interval = config.get("flush_interval_seconds", 60)
        self.batch_size = config.get("batch_size", 100)
        self.compression_enabled = config.get("compression_enabled", True)

        # Backpressure configuration
        self.backpressure_threshold = config.get("backpressure_threshold", 0.8)
        self.drop_threshold = config.get("drop_threshold", 0.95)

        # Buffer statistics
        self.stats = {
            "total_events": 0,
            "buffered_events": 0,
            "flushed_batches": 0,
            "dropped_events": 0,
            "buffer_overflows": 0,
            "compression_ratio": 0.0,
            "last_flush": None,
            "buffer_sizes": defaultdict(int),
            "processing_times": deque(maxlen=1000),
        }

        # Processing tasks
        self.processing_tasks = []
        self.running = False

        # Batch processors (callbacks)
        self.batch_processors = []

        # Priority queues
        self.high_priority_buffer = deque()
        self.medium_priority_buffer = deque()
        self.low_priority_buffer = deque()

        # Persistent storage for critical events
        self.persistent_storage_enabled = config.get("persistent_storage", True)
        self.temp_storage_dir = tempfile.mkdtemp()

    async def initialize(self):
        """Initialize buffer manager"""
        try:
            # Test Redis connection if available
            if self.redis_client:
                await self.redis_client.ping()
                logger.info("Redis connection verified for buffer persistence")

            # Start processing tasks
            await self._start_processing_tasks()

            logger.info("Buffer manager initialized successfully")

        except Exception as e:
            logger.error("Failed to initialize buffer manager", error=str(e))
            raise

    async def _start_processing_tasks(self):
        """Start background processing tasks"""
        self.running = True

        # Flush timer task
        flush_task = asyncio.create_task(self._flush_timer())
        self.processing_tasks.append(flush_task)

        # Backpressure monitor task
        monitor_task = asyncio.create_task(self._monitor_backpressure())
        self.processing_tasks.append(monitor_task)

        # Stats collection task
        stats_task = asyncio.create_task(self._collect_stats())
        self.processing_tasks.append(stats_task)

        # Persistent buffer recovery task
        if self.redis_client:
            recovery_task = asyncio.create_task(self._recover_persistent_buffers())
            self.processing_tasks.append(recovery_task)

        logger.info("Buffer processing tasks started")

    async def add_event(self, event: BaseEvent) -> bool:
        """Add event to buffer

        Args:
            event: Event to buffer

        Returns:
            True if event was buffered successfully
        """
        try:
            start_time = time.time()

            # Check buffer capacity and backpressure
            if await self._should_drop_event(event):
                self.stats["dropped_events"] += 1
                logger.warning(
                    "Event dropped due to buffer overflow",
                    event_id=event.id,
                    severity=event.severity,
                )
                return False

            # Determine buffer key
            buffer_key = self._get_buffer_key(event)

            # Add to appropriate priority queue
            await self._add_to_priority_buffer(event)

            # Add to categorized buffer
            async with self.buffer_locks[buffer_key]:
                self.event_buffers[buffer_key].append(event)
                self.stats["buffer_sizes"][buffer_key] += 1

            # Persist critical events immediately
            if event.severity in [Severity.CRITICAL, Severity.HIGH]:
                await self._persist_critical_event(event)

            # Update statistics
            self.stats["total_events"] += 1
            self.stats["buffered_events"] += 1

            processing_time = time.time() - start_time
            self.stats["processing_times"].append(processing_time)

            # Check if immediate flush is needed
            if await self._should_immediate_flush(buffer_key):
                await self._flush_buffer(buffer_key)

            return True

        except Exception as e:
            logger.error(
                "Error adding event to buffer", event_id=event.id, error=str(e)
            )
            return False

    def _get_buffer_key(self, event: BaseEvent) -> str:
        """Get buffer key for event categorization"""
        return f"{event.source}:{event.event_type}:{event.severity}"

    async def _add_to_priority_buffer(self, event: BaseEvent):
        """Add event to priority-based buffer"""
        try:
            if event.severity == Severity.CRITICAL:
                self.high_priority_buffer.append(event)
            elif event.severity == Severity.HIGH:
                self.high_priority_buffer.append(event)
            elif event.severity == Severity.MEDIUM:
                self.medium_priority_buffer.append(event)
            else:
                self.low_priority_buffer.append(event)

        except Exception as e:
            logger.error("Error adding to priority buffer", error=str(e))

    async def _should_drop_event(self, event: BaseEvent) -> bool:
        """Determine if event should be dropped due to backpressure"""
        try:
            total_buffered = sum(len(buffer) for buffer in self.event_buffers.values())
            total_capacity = (
                self.max_buffer_size * len(self.event_buffers)
                if self.event_buffers
                else self.max_buffer_size
            )

            utilization = total_buffered / total_capacity if total_capacity > 0 else 0

            # Never drop critical events
            if event.severity == Severity.CRITICAL:
                return False

            # Drop based on utilization thresholds
            if utilization >= self.drop_threshold:
                return True
            elif utilization >= self.backpressure_threshold:
                # Drop lower priority events more aggressively
                if event.severity == Severity.LOW and utilization > 0.85:
                    return True
                elif event.severity == Severity.INFO and utilization > 0.9:
                    return True

            return False

        except Exception as e:
            logger.error("Error checking drop condition", error=str(e))
            return False

    async def _persist_critical_event(self, event: BaseEvent):
        """Persist critical events for reliability"""
        try:
            if not self.persistent_storage_enabled:
                return

            event_data = event.dict()

            # Store in Redis if available
            if self.redis_client:
                key = f"critical_event:{event.id}"
                await self.redis_client.setex(
                    key, 3600, json.dumps(event_data, default=str)  # 1 hour TTL
                )

            # Also store in temporary file as backup
            import os

            temp_file = os.path.join(self.temp_storage_dir, f"critical_{event.id}.json")
            with open(temp_file, "w") as f:
                json.dump(event_data, f, default=str)

        except Exception as e:
            logger.error(
                "Error persisting critical event", event_id=event.id, error=str(e)
            )

    async def _should_immediate_flush(self, buffer_key: str) -> bool:
        """Check if buffer should be flushed immediately"""
        try:
            buffer_size = len(self.event_buffers[buffer_key])

            # Flush if buffer is full
            if buffer_size >= self.batch_size:
                return True

            # Flush if buffer has critical events
            buffer = self.event_buffers[buffer_key]
            if buffer and any(event.severity == Severity.CRITICAL for event in buffer):
                return True

            return False

        except Exception as e:
            logger.error("Error checking immediate flush condition", error=str(e))
            return False

    async def _flush_timer(self):
        """Periodic buffer flushing task"""
        try:
            while self.running:
                try:
                    await asyncio.sleep(self.flush_interval)

                    if not self.running:
                        break

                    # Flush all buffers
                    await self.flush_all()

                except Exception as e:
                    logger.error("Error in flush timer", error=str(e))
                    await asyncio.sleep(10)  # Wait before retrying

        except asyncio.CancelledError:
            logger.info("Flush timer cancelled")
        except Exception as e:
            logger.error("Fatal error in flush timer", error=str(e))

    async def flush_all(self):
        """Flush all buffers"""
        try:
            start_time = time.time()

            # Get all buffer keys
            buffer_keys = list(self.event_buffers.keys())

            # Flush each buffer
            flush_tasks = []
            for buffer_key in buffer_keys:
                if len(self.event_buffers[buffer_key]) > 0:
                    task = asyncio.create_task(self._flush_buffer(buffer_key))
                    flush_tasks.append(task)

            # Wait for all flushes to complete
            if flush_tasks:
                await asyncio.gather(*flush_tasks, return_exceptions=True)

            # Flush priority buffers
            await self._flush_priority_buffers()

            flush_time = time.time() - start_time
            self.stats["last_flush"] = datetime.utcnow().isoformat()

            logger.debug(
                "Buffer flush completed",
                flush_time=flush_time,
                buffers_flushed=len(flush_tasks),
            )

        except Exception as e:
            logger.error("Error flushing all buffers", error=str(e))

    async def _flush_buffer(self, buffer_key: str):
        """Flush a specific buffer"""
        try:
            async with self.buffer_locks[buffer_key]:
                buffer = self.event_buffers[buffer_key]

                if not buffer:
                    return

                # Create batch
                batch = []
                batch_size = min(len(buffer), self.batch_size)

                for _ in range(batch_size):
                    if buffer:
                        event = buffer.popleft()
                        batch.append(event)
                        self.stats["buffered_events"] -= 1
                        self.stats["buffer_sizes"][buffer_key] -= 1

            if batch:
                # Process batch
                await self._process_batch(batch, buffer_key)
                self.stats["flushed_batches"] += 1

        except Exception as e:
            logger.error("Error flushing buffer", buffer_key=buffer_key, error=str(e))

    async def _flush_priority_buffers(self):
        """Flush priority buffers in order"""
        try:
            # High priority first
            if self.high_priority_buffer:
                batch = []
                for _ in range(min(len(self.high_priority_buffer), self.batch_size)):
                    if self.high_priority_buffer:
                        batch.append(self.high_priority_buffer.popleft())

                if batch:
                    await self._process_batch(batch, "high_priority")

            # Medium priority
            if self.medium_priority_buffer:
                batch = []
                for _ in range(min(len(self.medium_priority_buffer), self.batch_size)):
                    if self.medium_priority_buffer:
                        batch.append(self.medium_priority_buffer.popleft())

                if batch:
                    await self._process_batch(batch, "medium_priority")

            # Low priority
            if self.low_priority_buffer:
                batch = []
                for _ in range(min(len(self.low_priority_buffer), self.batch_size)):
                    if self.low_priority_buffer:
                        batch.append(self.low_priority_buffer.popleft())

                if batch:
                    await self._process_batch(batch, "low_priority")

        except Exception as e:
            logger.error("Error flushing priority buffers", error=str(e))

    async def _process_batch(self, batch: List[BaseEvent], buffer_key: str):
        """Process a batch of events"""
        try:
            start_time = time.time()

            # Compress batch if enabled
            if self.compression_enabled:
                compressed_batch = await self._compress_batch(batch)
            else:
                compressed_batch = batch

            # Send to all registered processors
            processor_tasks = []
            for processor in self.batch_processors:
                task = asyncio.create_task(processor(compressed_batch, buffer_key))
                processor_tasks.append(task)

            # Wait for all processors to complete
            if processor_tasks:
                results = await asyncio.gather(*processor_tasks, return_exceptions=True)

                # Log any processor errors
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        logger.error(
                            "Batch processor error",
                            processor_index=i,
                            error=str(result),
                        )

            processing_time = time.time() - start_time

            logger.debug(
                "Batch processed successfully",
                buffer_key=buffer_key,
                batch_size=len(batch),
                processing_time=processing_time,
            )

        except Exception as e:
            logger.error(
                "Error processing batch",
                buffer_key=buffer_key,
                batch_size=len(batch),
                error=str(e),
            )

    async def _compress_batch(self, batch: List[BaseEvent]) -> List[BaseEvent]:
        """Compress batch events if beneficial"""
        try:
            # Simple compression: remove duplicate events within batch
            seen_hashes = set()
            compressed_batch = []

            for event in batch:
                # Create simple hash of event
                event_hash = hash((event.source, event.event_type, event.message))

                if event_hash not in seen_hashes:
                    seen_hashes.add(event_hash)
                    compressed_batch.append(event)

            compression_ratio = len(compressed_batch) / len(batch) if batch else 1.0
            self.stats["compression_ratio"] = compression_ratio

            if len(compressed_batch) < len(batch):
                logger.debug(
                    "Batch compressed",
                    original_size=len(batch),
                    compressed_size=len(compressed_batch),
                    ratio=compression_ratio,
                )

            return compressed_batch

        except Exception as e:
            logger.error("Error compressing batch", error=str(e))
            return batch

    def register_batch_processor(self, processor_func):
        """Register a batch processor function

        Args:
            processor_func: Async function that processes batches
        """
        self.batch_processors.append(processor_func)
        logger.info(
            "Batch processor registered", processor_count=len(self.batch_processors)
        )

    async def _monitor_backpressure(self):
        """Monitor buffer utilization and backpressure"""
        try:
            while self.running:
                try:
                    await asyncio.sleep(30)  # Check every 30 seconds

                    if not self.running:
                        break

                    # Calculate buffer utilization
                    total_events = sum(
                        len(buffer) for buffer in self.event_buffers.values()
                    )
                    total_capacity = self.max_buffer_size * max(
                        len(self.event_buffers), 1
                    )
                    utilization = (
                        total_events / total_capacity if total_capacity > 0 else 0
                    )

                    # Log warnings if utilization is high
                    if utilization > self.backpressure_threshold:
                        logger.warning(
                            "High buffer utilization detected",
                            utilization=utilization,
                            total_events=total_events,
                            buffer_count=len(self.event_buffers),
                        )

                    # Force flush if near capacity
                    if utilization > 0.9:
                        logger.warning("Emergency buffer flush triggered")
                        await self.flush_all()

                except Exception as e:
                    logger.error("Error in backpressure monitor", error=str(e))
                    await asyncio.sleep(60)

        except asyncio.CancelledError:
            logger.info("Backpressure monitor cancelled")
        except Exception as e:
            logger.error("Fatal error in backpressure monitor", error=str(e))

    async def _collect_stats(self):
        """Collect buffer statistics"""
        try:
            while self.running:
                try:
                    await asyncio.sleep(60)  # Collect stats every minute

                    if not self.running:
                        break

                    # Update buffer statistics
                    current_buffered = sum(
                        len(buffer) for buffer in self.event_buffers.values()
                    )
                    self.stats["buffered_events"] = current_buffered

                    # Calculate average processing time
                    if self.stats["processing_times"]:
                        avg_processing_time = sum(self.stats["processing_times"]) / len(
                            self.stats["processing_times"]
                        )
                    else:
                        avg_processing_time = 0.0

                    # Log periodic statistics
                    logger.info(
                        "Buffer statistics",
                        total_events=self.stats["total_events"],
                        buffered_events=current_buffered,
                        flushed_batches=self.stats["flushed_batches"],
                        dropped_events=self.stats["dropped_events"],
                        avg_processing_time=avg_processing_time,
                        buffer_count=len(self.event_buffers),
                    )

                except Exception as e:
                    logger.error("Error collecting stats", error=str(e))
                    await asyncio.sleep(60)

        except asyncio.CancelledError:
            logger.info("Stats collection cancelled")
        except Exception as e:
            logger.error("Fatal error in stats collection", error=str(e))

    async def _recover_persistent_buffers(self):
        """Recover buffers from persistent storage on startup"""
        try:
            if not self.redis_client:
                return

            # Recover critical events from Redis
            pattern = "critical_event:*"
            keys = await self.redis_client.keys(pattern)

            recovered_count = 0
            for key in keys:
                try:
                    event_data = await self.redis_client.get(key)
                    if event_data:
                        event_dict = json.loads(event_data)
                        event = BaseEvent(**event_dict)
                        await self.add_event(event)
                        recovered_count += 1

                        # Remove from persistent storage after recovery
                        await self.redis_client.delete(key)

                except Exception as e:
                    logger.error("Error recovering event", key=key, error=str(e))

            if recovered_count > 0:
                logger.info("Critical events recovered", count=recovered_count)

        except Exception as e:
            logger.error("Error recovering persistent buffers", error=str(e))

    def get_buffer_status(self) -> Dict[str, Any]:
        """Get current buffer status and statistics"""
        buffer_info = {}

        for buffer_key, buffer in self.event_buffers.items():
            buffer_info[buffer_key] = {
                "size": len(buffer),
                "oldest_event": buffer[0].timestamp.isoformat() if buffer else None,
                "newest_event": buffer[-1].timestamp.isoformat() if buffer else None,
            }

        return {
            "statistics": dict(self.stats),
            "buffer_info": buffer_info,
            "priority_buffers": {
                "high_priority": len(self.high_priority_buffer),
                "medium_priority": len(self.medium_priority_buffer),
                "low_priority": len(self.low_priority_buffer),
            },
            "configuration": {
                "max_buffer_size": self.max_buffer_size,
                "flush_interval": self.flush_interval,
                "batch_size": self.batch_size,
                "compression_enabled": self.compression_enabled,
                "backpressure_threshold": self.backpressure_threshold,
            },
            "total_processors": len(self.batch_processors),
        }

    async def force_flush(self, buffer_key: Optional[str] = None):
        """Force immediate flush of buffers

        Args:
            buffer_key: Specific buffer to flush, or None for all buffers
        """
        try:
            if buffer_key:
                await self._flush_buffer(buffer_key)
            else:
                await self.flush_all()

            logger.info("Manual flush completed", buffer_key=buffer_key)

        except Exception as e:
            logger.error("Error in manual flush", buffer_key=buffer_key, error=str(e))

    async def clear_buffers(self):
        """Clear all buffers (emergency operation)"""
        try:
            cleared_events = 0

            # Clear all categorized buffers
            for buffer_key in list(self.event_buffers.keys()):
                async with self.buffer_locks[buffer_key]:
                    cleared_events += len(self.event_buffers[buffer_key])
                    self.event_buffers[buffer_key].clear()
                    self.stats["buffer_sizes"][buffer_key] = 0

            # Clear priority buffers
            cleared_events += len(self.high_priority_buffer)
            cleared_events += len(self.medium_priority_buffer)
            cleared_events += len(self.low_priority_buffer)

            self.high_priority_buffer.clear()
            self.medium_priority_buffer.clear()
            self.low_priority_buffer.clear()

            self.stats["buffered_events"] = 0
            self.stats["dropped_events"] += cleared_events

            logger.warning("All buffers cleared", cleared_events=cleared_events)

        except Exception as e:
            logger.error("Error clearing buffers", error=str(e))

    async def start_processing(self):
        """Start buffer processing (called by main application)"""
        if not self.running:
            await self._start_processing_tasks()

    async def stop(self):
        """Stop buffer manager and cleanup"""
        self.running = False

        # Flush all remaining events
        try:
            await self.flush_all()
        except Exception as e:
            logger.error("Error during final flush", error=str(e))

        # Cancel processing tasks
        for task in self.processing_tasks:
            if not task.done():
                task.cancel()

        # Wait for tasks to complete
        if self.processing_tasks:
            await asyncio.gather(*self.processing_tasks, return_exceptions=True)

        # Cleanup temporary storage
        try:
            import shutil

            shutil.rmtree(self.temp_storage_dir, ignore_errors=True)
        except Exception as e:
            logger.error("Error cleaning up temp storage", error=str(e))

        logger.info("Buffer manager stopped", final_stats=self.get_buffer_status())
