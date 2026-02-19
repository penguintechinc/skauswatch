"""
Thread Pool Management for SkausWatch Services

Provides comprehensive thread pool management for CPU-bound and I/O-bound
tasks with intelligent sizing, health monitoring, and graceful shutdown.
"""

import asyncio
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    TypeVar,
    Union,
    Generic,
    Awaitable,
    Set,
    Tuple,
)
from uuid import uuid4
import multiprocessing
import psutil
import weakref

logger = logging.getLogger(__name__)

T = TypeVar("T")
F = TypeVar("F", bound=Callable[..., Any])


class TaskType(Enum):
    """Types of tasks for different thread pools"""

    CPU_BOUND = "cpu_bound"
    IO_BOUND = "io_bound"
    MIXED = "mixed"


class PoolStatus(Enum):
    """Thread pool status"""

    HEALTHY = "healthy"
    OVERLOADED = "overloaded"
    SHUTTING_DOWN = "shutting_down"
    SHUTDOWN = "shutdown"


@dataclass
class ThreadPoolConfig:
    """Configuration for thread pool"""

    min_workers: int = 1
    max_workers: int = 10
    idle_timeout: float = 60.0
    queue_size: int = 1000
    task_timeout: float = 300.0
    auto_scale: bool = True
    scale_up_threshold: float = 0.8  # Scale up when queue is 80% full
    scale_down_threshold: float = 0.3  # Scale down when queue is 30% full
    health_check_interval: float = 30.0
    metrics_enabled: bool = True


@dataclass
class TaskMetrics:
    """Metrics for task execution"""

    total_submitted: int = 0
    total_completed: int = 0
    total_failed: int = 0
    total_timed_out: int = 0
    average_execution_time: float = 0.0
    peak_queue_size: int = 0
    active_tasks: int = 0
    execution_times: List[float] = field(default_factory=list)


@dataclass
class PoolMetrics:
    """Metrics for thread pool"""

    active_threads: int = 0
    total_threads: int = 0
    queue_size: int = 0
    tasks_per_second: float = 0.0
    cpu_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    uptime_seconds: float = 0.0
    status: PoolStatus = PoolStatus.HEALTHY


class ThreadSafeTaskTracker:
    """Thread-safe task tracking"""

    def __init__(self):
        self._lock = threading.Lock()
        self._tasks: Dict[str, Dict[str, Any]] = {}

    def add_task(self, task_id: str, task_info: Dict[str, Any]) -> None:
        """Add task to tracker"""
        with self._lock:
            self._tasks[task_id] = {
                **task_info,
                "start_time": time.time(),
                "status": "running",
            }

    def complete_task(
        self, task_id: str, result: Any = None, error: Optional[Exception] = None
    ) -> None:
        """Mark task as completed"""
        with self._lock:
            if task_id in self._tasks:
                task = self._tasks[task_id]
                task["end_time"] = time.time()
                task["execution_time"] = task["end_time"] - task["start_time"]
                task["status"] = "failed" if error else "completed"
                task["result"] = result
                task["error"] = error

    def get_task_info(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get task information"""
        with self._lock:
            return self._tasks.get(task_id, {}).copy()

    def get_active_tasks(self) -> List[Dict[str, Any]]:
        """Get all active tasks"""
        with self._lock:
            return [
                task.copy()
                for task in self._tasks.values()
                if task.get("status") == "running"
            ]

    def cleanup_completed_tasks(self, max_age_seconds: float = 300.0) -> int:
        """Remove old completed tasks"""
        current_time = time.time()
        removed_count = 0

        with self._lock:
            task_ids_to_remove = []
            for task_id, task in self._tasks.items():
                if (
                    task.get("status") in ["completed", "failed"]
                    and task.get("end_time", 0) < current_time - max_age_seconds
                ):
                    task_ids_to_remove.append(task_id)

            for task_id in task_ids_to_remove:
                del self._tasks[task_id]
                removed_count += 1

        return removed_count


class SmartThreadPoolExecutor(ThreadPoolExecutor):
    """Enhanced ThreadPoolExecutor with auto-scaling and health monitoring"""

    def __init__(
        self,
        pool_name: str,
        config: ThreadPoolConfig,
        task_type: TaskType = TaskType.MIXED,
    ):
        # Initialize with min_workers
        super().__init__(
            max_workers=config.min_workers, thread_name_prefix=f"{pool_name}_worker"
        )

        self.pool_name = pool_name
        self.config = config
        self.task_type = task_type
        self.start_time = time.time()

        # Metrics and tracking
        self.task_metrics = TaskMetrics()
        self.task_tracker = ThreadSafeTaskTracker()
        self.metrics_lock = threading.Lock()

        # Health monitoring
        self.status = PoolStatus.HEALTHY
        self.last_health_check = time.time()
        self.health_check_task: Optional[asyncio.Task] = None

        # Auto-scaling
        self._target_workers = config.min_workers
        self._last_scale_time = time.time()
        self._scale_cooldown = 30.0  # Minimum time between scaling operations

        # Shutdown management
        self._shutdown_event = threading.Event()
        self._shutdown_timeout = 30.0

    def submit_task(
        self,
        func: Callable[..., T],
        *args,
        task_id: Optional[str] = None,
        timeout: Optional[float] = None,
        priority: int = 0,
        **kwargs,
    ) -> Tuple[str, Future[T]]:
        """Submit task with enhanced tracking"""
        if self.status == PoolStatus.SHUTDOWN:
            raise RuntimeError(f"Pool {self.pool_name} is shutdown")

        task_id = task_id or str(uuid4())
        timeout = timeout or self.config.task_timeout

        # Track task submission
        self.task_tracker.add_task(
            task_id,
            {
                "function": func.__name__,
                "timeout": timeout,
                "priority": priority,
                "args_count": len(args),
                "kwargs_count": len(kwargs),
            },
        )

        # Wrap function with tracking and timeout
        wrapped_func = self._wrap_task_execution(func, task_id, timeout)

        # Submit to thread pool
        future = super().submit(wrapped_func, *args, **kwargs)

        # Update metrics
        with self.metrics_lock:
            self.task_metrics.total_submitted += 1
            self.task_metrics.active_tasks += 1

        # Check if scaling is needed
        self._check_auto_scaling()

        return task_id, future

    def _wrap_task_execution(
        self, func: Callable[..., T], task_id: str, timeout: float
    ) -> Callable[..., T]:
        """Wrap task execution with monitoring and timeout"""

        def wrapper(*args, **kwargs) -> T:
            start_time = time.time()
            result = None
            error = None

            try:
                # Simple timeout implementation
                if timeout and timeout > 0:
                    # For CPU-bound tasks, timeout is advisory only
                    # For I/O-bound tasks, the function should handle timeout internally
                    result = func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

            except Exception as e:
                error = e
                logger.error(f"Task {task_id} failed: {e}")
                raise
            finally:
                # Update tracking and metrics
                execution_time = time.time() - start_time
                self.task_tracker.complete_task(task_id, result, error)

                with self.metrics_lock:
                    self.task_metrics.active_tasks -= 1
                    self.task_metrics.execution_times.append(execution_time)

                    # Keep only last 1000 execution times for memory efficiency
                    if len(self.task_metrics.execution_times) > 1000:
                        self.task_metrics.execution_times = (
                            self.task_metrics.execution_times[-1000:]
                        )

                    if error:
                        self.task_metrics.total_failed += 1
                    else:
                        self.task_metrics.total_completed += 1

                    # Update average execution time
                    if self.task_metrics.execution_times:
                        self.task_metrics.average_execution_time = sum(
                            self.task_metrics.execution_times
                        ) / len(self.task_metrics.execution_times)

            return result

        return wrapper

    def _check_auto_scaling(self) -> None:
        """Check if auto-scaling is needed"""
        if not self.config.auto_scale:
            return

        current_time = time.time()
        if current_time - self._last_scale_time < self._scale_cooldown:
            return

        with self.metrics_lock:
            queue_utilization = min(
                1.0, self.task_metrics.active_tasks / max(1, self.config.queue_size)
            )

        current_workers = (
            self._threads.__len__()
            if hasattr(self, "_threads")
            else self._target_workers
        )

        # Scale up if queue utilization is high
        if (
            queue_utilization >= self.config.scale_up_threshold
            and current_workers < self.config.max_workers
        ):
            new_workers = min(self.config.max_workers, current_workers + 1)
            self._scale_pool(new_workers)
            logger.info(f"Scaling up {self.pool_name} to {new_workers} workers")

        # Scale down if queue utilization is low
        elif (
            queue_utilization <= self.config.scale_down_threshold
            and current_workers > self.config.min_workers
        ):
            new_workers = max(self.config.min_workers, current_workers - 1)
            self._scale_pool(new_workers)
            logger.info(f"Scaling down {self.pool_name} to {new_workers} workers")

    def _scale_pool(self, target_workers: int) -> None:
        """Scale the thread pool to target size"""
        try:
            # This is a simplified scaling approach
            # In practice, you might need more sophisticated pool resizing
            self._max_workers = target_workers
            self._target_workers = target_workers
            self._last_scale_time = time.time()
        except Exception as e:
            logger.error(f"Failed to scale pool {self.pool_name}: {e}")

    def get_metrics(self) -> PoolMetrics:
        """Get current pool metrics"""
        with self.metrics_lock:
            # Calculate CPU usage (simplified)
            try:
                cpu_percent = psutil.Process().cpu_percent()
                memory_mb = psutil.Process().memory_info().rss / 1024 / 1024
            except:
                cpu_percent = 0.0
                memory_mb = 0.0

            # Calculate tasks per second
            uptime = time.time() - self.start_time
            tasks_per_second = (
                self.task_metrics.total_completed / max(1, uptime)
                if uptime > 0
                else 0.0
            )

            return PoolMetrics(
                active_threads=getattr(self, "_threads", {})
                and len(self._threads)
                or 0,
                total_threads=self._target_workers,
                queue_size=self.task_metrics.active_tasks,
                tasks_per_second=tasks_per_second,
                cpu_usage_percent=cpu_percent,
                memory_usage_mb=memory_mb,
                uptime_seconds=uptime,
                status=self.status,
            )

    def get_task_metrics(self) -> TaskMetrics:
        """Get task metrics"""
        with self.metrics_lock:
            return TaskMetrics(
                total_submitted=self.task_metrics.total_submitted,
                total_completed=self.task_metrics.total_completed,
                total_failed=self.task_metrics.total_failed,
                total_timed_out=self.task_metrics.total_timed_out,
                average_execution_time=self.task_metrics.average_execution_time,
                peak_queue_size=self.task_metrics.peak_queue_size,
                active_tasks=self.task_metrics.active_tasks,
                execution_times=self.task_metrics.execution_times.copy(),
            )

    async def health_check(self) -> bool:
        """Perform health check"""
        try:
            # Check if any threads are hung
            active_tasks = self.task_tracker.get_active_tasks()
            current_time = time.time()

            hung_tasks = [
                task
                for task in active_tasks
                if current_time - task.get("start_time", current_time)
                > self.config.task_timeout * 2
            ]

            if hung_tasks:
                logger.warning(
                    f"Found {len(hung_tasks)} potentially hung tasks in {self.pool_name}"
                )
                self.status = PoolStatus.OVERLOADED
                return False

            # Check resource utilization
            metrics = self.get_metrics()
            if metrics.cpu_usage_percent > 95.0:
                self.status = PoolStatus.OVERLOADED
                return False

            self.status = PoolStatus.HEALTHY
            self.last_health_check = time.time()
            return True

        except Exception as e:
            logger.error(f"Health check failed for {self.pool_name}: {e}")
            self.status = PoolStatus.OVERLOADED
            return False

    def shutdown_gracefully(self, timeout: Optional[float] = None) -> bool:
        """Gracefully shutdown the pool"""
        timeout = timeout or self._shutdown_timeout

        logger.info(f"Initiating graceful shutdown of {self.pool_name}")
        self.status = PoolStatus.SHUTTING_DOWN
        self._shutdown_event.set()

        try:
            # Wait for active tasks to complete
            self.shutdown(wait=True, cancel_futures=False)

            # Cleanup completed tasks
            self.task_tracker.cleanup_completed_tasks(0)

            self.status = PoolStatus.SHUTDOWN
            logger.info(f"Successfully shutdown {self.pool_name}")
            return True

        except Exception as e:
            logger.error(f"Error during shutdown of {self.pool_name}: {e}")
            return False


class ThreadPoolManager:
    """Centralized thread pool management"""

    def __init__(self):
        self.pools: Dict[str, SmartThreadPoolExecutor] = {}
        self.default_configs: Dict[TaskType, ThreadPoolConfig] = {
            TaskType.CPU_BOUND: ThreadPoolConfig(
                min_workers=1,
                max_workers=multiprocessing.cpu_count(),
                task_timeout=300.0,
            ),
            TaskType.IO_BOUND: ThreadPoolConfig(
                min_workers=2, max_workers=50, task_timeout=30.0
            ),
            TaskType.MIXED: ThreadPoolConfig(
                min_workers=2, max_workers=20, task_timeout=60.0
            ),
        }
        self.health_check_interval = 60.0
        self.health_check_task: Optional[asyncio.Task] = None
        self._shutdown = False

    def create_pool(
        self,
        name: str,
        task_type: TaskType = TaskType.MIXED,
        config: Optional[ThreadPoolConfig] = None,
    ) -> SmartThreadPoolExecutor:
        """Create a new thread pool"""
        if name in self.pools:
            raise ValueError(f"Pool '{name}' already exists")

        config = config or self.default_configs[task_type]
        pool = SmartThreadPoolExecutor(name, config, task_type)
        self.pools[name] = pool

        logger.info(f"Created thread pool '{name}' for {task_type.value} tasks")
        return pool

    def get_pool(self, name: str) -> Optional[SmartThreadPoolExecutor]:
        """Get existing thread pool"""
        return self.pools.get(name)

    def get_or_create_pool(
        self,
        name: str,
        task_type: TaskType = TaskType.MIXED,
        config: Optional[ThreadPoolConfig] = None,
    ) -> SmartThreadPoolExecutor:
        """Get existing pool or create new one"""
        pool = self.get_pool(name)
        if pool is None:
            pool = self.create_pool(name, task_type, config)
        return pool

    async def submit_task(
        self,
        pool_name: str,
        func: Callable[..., T],
        *args,
        task_type: TaskType = TaskType.MIXED,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> Tuple[str, T]:
        """Submit task to pool (async wrapper)"""
        pool = self.get_or_create_pool(pool_name, task_type)
        task_id, future = pool.submit_task(func, *args, timeout=timeout, **kwargs)

        # Convert Future to awaitable
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, future.result)

        return task_id, result

    def submit_task_sync(
        self,
        pool_name: str,
        func: Callable[..., T],
        *args,
        task_type: TaskType = TaskType.MIXED,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> Tuple[str, Future[T]]:
        """Submit task to pool (synchronous)"""
        pool = self.get_or_create_pool(pool_name, task_type)
        return pool.submit_task(func, *args, timeout=timeout, **kwargs)

    def get_all_metrics(self) -> Dict[str, Dict[str, Any]]:
        """Get metrics for all pools"""
        metrics = {}
        for name, pool in self.pools.items():
            metrics[name] = {
                "pool_metrics": pool.get_metrics().__dict__,
                "task_metrics": pool.get_task_metrics().__dict__,
            }
        return metrics

    async def start_health_monitoring(self) -> None:
        """Start health monitoring for all pools"""
        if self.health_check_task is not None:
            return

        self.health_check_task = asyncio.create_task(self._health_monitor_loop())

    async def _health_monitor_loop(self) -> None:
        """Health monitoring loop"""
        while not self._shutdown:
            try:
                for name, pool in self.pools.items():
                    healthy = await pool.health_check()
                    if not healthy:
                        logger.warning(f"Pool {name} failed health check")

                # Cleanup completed tasks in all pools
                for pool in self.pools.values():
                    pool.task_tracker.cleanup_completed_tasks()

            except Exception as e:
                logger.error(f"Health monitoring error: {e}")

            await asyncio.sleep(self.health_check_interval)

    async def shutdown_all(self, timeout: float = 30.0) -> None:
        """Shutdown all pools"""
        self._shutdown = True

        if self.health_check_task:
            self.health_check_task.cancel()

        # Shutdown all pools concurrently
        shutdown_tasks = []
        for name, pool in self.pools.items():
            task = asyncio.create_task(
                asyncio.get_running_loop().run_in_executor(
                    None, pool.shutdown_gracefully, timeout
                )
            )
            shutdown_tasks.append((name, task))

        # Wait for all shutdowns to complete
        for name, task in shutdown_tasks:
            try:
                success = await asyncio.wait_for(task, timeout + 10)
                if success:
                    logger.info(f"Successfully shutdown pool {name}")
                else:
                    logger.warning(f"Pool {name} shutdown with warnings")
            except asyncio.TimeoutError:
                logger.error(f"Timeout shutting down pool {name}")

        self.pools.clear()


# Specialized pool managers


class CPUBoundTaskManager:
    """Specialized manager for CPU-bound tasks"""

    def __init__(self, pool_manager: ThreadPoolManager):
        self.pool_manager = pool_manager
        self.pool_name = "cpu_bound_pool"

        # Create optimized CPU-bound pool
        config = ThreadPoolConfig(
            min_workers=1,
            max_workers=multiprocessing.cpu_count(),
            task_timeout=600.0,  # Longer timeout for CPU-bound tasks
            auto_scale=True,
            scale_up_threshold=0.7,
            scale_down_threshold=0.2,
        )

        self.pool = pool_manager.create_pool(self.pool_name, TaskType.CPU_BOUND, config)

    async def submit_computation(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Submit CPU-intensive computation"""
        _, result = await self.pool_manager.submit_task(
            self.pool_name, func, *args, **kwargs
        )
        return result


class IOBoundTaskManager:
    """Specialized manager for I/O-bound tasks"""

    def __init__(self, pool_manager: ThreadPoolManager):
        self.pool_manager = pool_manager
        self.pool_name = "io_bound_pool"

        # Create optimized I/O-bound pool
        config = ThreadPoolConfig(
            min_workers=5,
            max_workers=100,  # Higher concurrency for I/O
            task_timeout=30.0,  # Shorter timeout for I/O operations
            auto_scale=True,
            scale_up_threshold=0.8,
            scale_down_threshold=0.3,
        )

        self.pool = pool_manager.create_pool(self.pool_name, TaskType.IO_BOUND, config)

    async def submit_io_task(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Submit I/O-intensive task"""
        _, result = await self.pool_manager.submit_task(
            self.pool_name, func, *args, **kwargs
        )
        return result


class AsyncThreadPoolExecutor:
    """Async wrapper for thread pool operations"""

    def __init__(self, pool_manager: ThreadPoolManager):
        self.pool_manager = pool_manager

    async def run_in_thread(
        self,
        func: Callable[..., T],
        *args,
        pool_name: str = "default",
        task_type: TaskType = TaskType.MIXED,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> T:
        """Run function in thread pool"""
        _, result = await self.pool_manager.submit_task(
            pool_name, func, *args, task_type=task_type, timeout=timeout, **kwargs
        )
        return result


# Decorators


def thread_pool_task(
    pool_name: str = "default",
    task_type: TaskType = TaskType.MIXED,
    timeout: Optional[float] = None,
    pool_manager: Optional[ThreadPoolManager] = None,
) -> Callable[[F], F]:
    """Decorator to run function in thread pool"""

    def decorator(func: F) -> F:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            nonlocal pool_manager
            if pool_manager is None:
                pool_manager = ThreadPoolManager()

            _, result = await pool_manager.submit_task(
                pool_name, func, *args, task_type=task_type, timeout=timeout, **kwargs
            )
            return result

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            nonlocal pool_manager
            if pool_manager is None:
                pool_manager = ThreadPoolManager()

            _, future = pool_manager.submit_task_sync(
                pool_name, func, *args, task_type=task_type, timeout=timeout, **kwargs
            )
            return future.result()

        # Return appropriate wrapper based on whether we're in async context
        try:
            asyncio.get_running_loop()
            return async_wrapper
        except RuntimeError:
            return sync_wrapper

    return decorator


# Global thread pool manager instance
_global_pool_manager: Optional[ThreadPoolManager] = None


def get_global_pool_manager() -> ThreadPoolManager:
    """Get global thread pool manager instance"""
    global _global_pool_manager
    if _global_pool_manager is None:
        _global_pool_manager = ThreadPoolManager()
    return _global_pool_manager


async def cleanup_global_pools():
    """Cleanup global thread pools"""
    global _global_pool_manager
    if _global_pool_manager is not None:
        await _global_pool_manager.shutdown_all()
        _global_pool_manager = None
