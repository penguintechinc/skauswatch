"""
Async Utilities for SkausWatch Services

Provides comprehensive async patterns, decorators, and utilities
for efficient concurrent programming across all services.
"""

import asyncio
import functools
import logging
import time
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    TypeVar,
    Union,
    AsyncIterator,
    Tuple,
    Set,
)
from uuid import uuid4
import weakref

logger = logging.getLogger(__name__)

T = TypeVar("T")
F = TypeVar("F", bound=Callable[..., Awaitable[Any]])


class CircuitBreakerState(Enum):
    """Circuit breaker states"""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class RetryConfig:
    """Configuration for async retry decorator"""

    max_attempts: int = 3
    delay: float = 1.0
    backoff_factor: float = 2.0
    max_delay: float = 60.0
    exceptions: Tuple[type, ...] = (Exception,)
    jitter: bool = True
    exponential_base: float = 2.0


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""

    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_max_calls: int = 3
    expected_exception: type = Exception


@dataclass
class SemaphoreConfig:
    """Configuration for semaphore-based rate limiting"""

    max_concurrent: int = 10
    timeout: Optional[float] = None


@dataclass
class BatchConfig:
    """Configuration for batch processing"""

    batch_size: int = 100
    max_wait_time: float = 1.0
    max_concurrent_batches: int = 5


class AsyncRetry:
    """Advanced async retry mechanism with exponential backoff and jitter"""

    def __init__(self, config: RetryConfig):
        self.config = config

    async def __call__(self, func: Callable[..., Awaitable[T]], *args, **kwargs) -> T:
        """Execute function with retry logic"""
        last_exception = None

        for attempt in range(1, self.config.max_attempts + 1):
            try:
                return await func(*args, **kwargs)
            except self.config.exceptions as e:
                last_exception = e
                if attempt == self.config.max_attempts:
                    break

                delay = self._calculate_delay(attempt)
                logger.warning(
                    f"Attempt {attempt} failed, retrying in {delay:.2f}s: {str(e)}"
                )
                await asyncio.sleep(delay)

        if last_exception:
            raise last_exception

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay with exponential backoff and jitter"""
        delay = self.config.delay * (self.config.exponential_base ** (attempt - 1))
        delay = min(delay, self.config.max_delay)

        if self.config.jitter:
            import random

            delay = delay * (0.5 + random.random() * 0.5)

        return delay


class AsyncCircuitBreaker:
    """Circuit breaker pattern for async operations"""

    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.half_open_attempts = 0
        self._lock = asyncio.Lock()

    async def __call__(self, func: Callable[..., Awaitable[T]], *args, **kwargs) -> T:
        """Execute function with circuit breaker protection"""
        async with self._lock:
            if self.state == CircuitBreakerState.OPEN:
                if self._should_attempt_reset():
                    self.state = CircuitBreakerState.HALF_OPEN
                    self.half_open_attempts = 0
                else:
                    raise Exception("Circuit breaker is OPEN")

            elif self.state == CircuitBreakerState.HALF_OPEN:
                if self.half_open_attempts >= self.config.half_open_max_calls:
                    raise Exception("Circuit breaker is HALF_OPEN - max calls exceeded")

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except self.config.expected_exception as e:
            await self._on_failure()
            raise

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        if self.last_failure_time is None:
            return True
        return time.time() - self.last_failure_time >= self.config.recovery_timeout

    async def _on_success(self):
        """Handle successful call"""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.CLOSED
            self.failure_count = 0
            self.half_open_attempts = 0
            logger.info("Circuit breaker reset to CLOSED")

    async def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.OPEN
            logger.warning("Circuit breaker opened from HALF_OPEN")
        elif self.failure_count >= self.config.failure_threshold:
            self.state = CircuitBreakerState.OPEN
            logger.warning("Circuit breaker opened due to failure threshold")

        if self.state == CircuitBreakerState.HALF_OPEN:
            self.half_open_attempts += 1


class AsyncSemaphore:
    """Advanced semaphore with timeout and priority support"""

    def __init__(self, config: SemaphoreConfig):
        self.config = config
        self.semaphore = asyncio.Semaphore(config.max_concurrent)
        self.active_tasks: Set[str] = set()

    @asynccontextmanager
    async def acquire(
        self, task_id: Optional[str] = None, timeout: Optional[float] = None
    ):
        """Acquire semaphore with optional timeout"""
        if task_id is None:
            task_id = str(uuid4())

        timeout = timeout or self.config.timeout

        try:
            if timeout:
                await asyncio.wait_for(self.semaphore.acquire(), timeout)
            else:
                await self.semaphore.acquire()

            self.active_tasks.add(task_id)
            logger.debug(f"Acquired semaphore for task {task_id}")
            yield task_id

        except asyncio.TimeoutError:
            raise TimeoutError(f"Failed to acquire semaphore within {timeout}s")
        finally:
            if task_id in self.active_tasks:
                self.active_tasks.remove(task_id)
                self.semaphore.release()
                logger.debug(f"Released semaphore for task {task_id}")


class AsyncBatchProcessor(Generic[T]):
    """Batch processor for efficient bulk operations"""

    def __init__(
        self, config: BatchConfig, processor: Callable[[List[T]], Awaitable[Any]]
    ):
        self.config = config
        self.processor = processor
        self.queue = asyncio.Queue()
        self.semaphore = asyncio.Semaphore(config.max_concurrent_batches)
        self.processing_task: Optional[asyncio.Task] = None
        self._shutdown = False

    async def start(self):
        """Start the batch processor"""
        self.processing_task = asyncio.create_task(self._process_batches())

    async def stop(self):
        """Stop the batch processor"""
        self._shutdown = True
        if self.processing_task:
            await self.processing_task

    async def submit(self, item: T) -> None:
        """Submit item for batch processing"""
        await self.queue.put(item)

    async def _process_batches(self):
        """Main batch processing loop"""
        while not self._shutdown or not self.queue.empty():
            batch = []
            deadline = time.time() + self.config.max_wait_time

            # Collect items for batch
            while (
                len(batch) < self.config.batch_size
                and time.time() < deadline
                and not self._shutdown
            ):
                try:
                    item = await asyncio.wait_for(
                        self.queue.get(), timeout=max(0.1, deadline - time.time())
                    )
                    batch.append(item)
                except asyncio.TimeoutError:
                    break

            if batch:
                # Process batch concurrently
                async with self.semaphore:
                    try:
                        await self.processor(batch)
                        logger.debug(f"Processed batch of {len(batch)} items")
                    except Exception as e:
                        logger.error(f"Batch processing failed: {e}")


class AsyncTaskManager:
    """Advanced task management with lifecycle control"""

    def __init__(self):
        self.tasks: Dict[str, asyncio.Task] = {}
        self.task_groups: Dict[str, Set[str]] = {}
        self._cleanup_interval = 60.0
        self._cleanup_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the task manager"""
        self._cleanup_task = asyncio.create_task(self._cleanup_completed_tasks())

    async def stop(self):
        """Stop all tasks and cleanup"""
        # Cancel all active tasks
        for task in self.tasks.values():
            if not task.done():
                task.cancel()

        # Wait for tasks to complete or timeout
        if self.tasks:
            await asyncio.gather(*self.tasks.values(), return_exceptions=True)

        if self._cleanup_task:
            self._cleanup_task.cancel()

        self.tasks.clear()
        self.task_groups.clear()

    def create_task(
        self,
        coro: Awaitable[T],
        name: Optional[str] = None,
        group: Optional[str] = None,
    ) -> str:
        """Create and track a task"""
        task_id = name or str(uuid4())
        task = asyncio.create_task(coro, name=task_id)
        self.tasks[task_id] = task

        if group:
            if group not in self.task_groups:
                self.task_groups[group] = set()
            self.task_groups[group].add(task_id)

        return task_id

    async def wait_for_task(self, task_id: str, timeout: Optional[float] = None) -> Any:
        """Wait for a specific task to complete"""
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not found")

        task = self.tasks[task_id]
        if timeout:
            return await asyncio.wait_for(task, timeout)
        else:
            return await task

    async def wait_for_group(
        self, group: str, timeout: Optional[float] = None
    ) -> List[Any]:
        """Wait for all tasks in a group to complete"""
        if group not in self.task_groups:
            return []

        task_ids = list(self.task_groups[group])
        tasks = [self.tasks[task_id] for task_id in task_ids if task_id in self.tasks]

        if timeout:
            return await asyncio.wait_for(asyncio.gather(*tasks), timeout)
        else:
            return await asyncio.gather(*tasks, return_exceptions=True)

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a specific task"""
        if task_id in self.tasks:
            self.tasks[task_id].cancel()
            return True
        return False

    def cancel_group(self, group: str) -> int:
        """Cancel all tasks in a group"""
        if group not in self.task_groups:
            return 0

        cancelled = 0
        for task_id in self.task_groups[group]:
            if self.cancel_task(task_id):
                cancelled += 1

        return cancelled

    async def _cleanup_completed_tasks(self):
        """Periodically cleanup completed tasks"""
        while True:
            try:
                await asyncio.sleep(self._cleanup_interval)

                # Remove completed tasks
                completed_tasks = [
                    task_id for task_id, task in self.tasks.items() if task.done()
                ]

                for task_id in completed_tasks:
                    del self.tasks[task_id]

                    # Remove from groups
                    for group_tasks in self.task_groups.values():
                        group_tasks.discard(task_id)

                if completed_tasks:
                    logger.debug(f"Cleaned up {len(completed_tasks)} completed tasks")

            except Exception as e:
                logger.error(f"Task cleanup failed: {e}")


class AsyncQueue(Generic[T]):
    """Enhanced async queue with priority and timeout support"""

    def __init__(self, maxsize: int = 0, priority_queue: bool = False):
        if priority_queue:
            import heapq

            self._queue = []
            self._index = 0
            self._get_item = lambda: heapq.heappop(self._queue)[2]
            self._put_item = self._put_priority_item
        else:
            self._queue = asyncio.Queue(maxsize)
            self._get_item = self._queue.get
            self._put_item = self._queue.put

        self.priority_queue = priority_queue
        self.maxsize = maxsize

    def _put_priority_item(self, item: Tuple[int, T]):
        """Put item in priority queue"""
        import heapq

        priority, value = item
        heapq.heappush(self._queue, (priority, self._index, value))
        self._index += 1

    async def put(
        self, item: T, priority: int = 0, timeout: Optional[float] = None
    ) -> None:
        """Put item in queue"""
        if self.priority_queue:
            if timeout:
                await asyncio.wait_for(self._put_item((priority, item)), timeout)
            else:
                await self._put_item((priority, item))
        else:
            if timeout:
                await asyncio.wait_for(self._put_item(item), timeout)
            else:
                await self._put_item(item)

    async def get(self, timeout: Optional[float] = None) -> T:
        """Get item from queue"""
        if timeout:
            return await asyncio.wait_for(self._get_item(), timeout)
        else:
            return await self._get_item()

    def qsize(self) -> int:
        """Get queue size"""
        if self.priority_queue:
            return len(self._queue)
        else:
            return self._queue.qsize()

    def empty(self) -> bool:
        """Check if queue is empty"""
        return self.qsize() == 0


class AsyncContextManager:
    """Base class for async context managers with proper cleanup"""

    def __init__(self):
        self._entered = False
        self._cleanup_handlers: List[Callable[[], Awaitable[None]]] = []

    async def __aenter__(self):
        if self._entered:
            raise RuntimeError("Context manager already entered")
        self._entered = True
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        try:
            await self._cleanup()
        finally:
            self._entered = False

    @abstractmethod
    async def _setup(self):
        """Setup resources"""
        pass

    async def _cleanup(self):
        """Cleanup resources"""
        exceptions = []

        for handler in reversed(self._cleanup_handlers):
            try:
                await handler()
            except Exception as e:
                exceptions.append(e)
                logger.error(f"Cleanup handler failed: {e}")

        if exceptions:
            # Raise the first exception if any occurred
            raise exceptions[0]

    def add_cleanup_handler(self, handler: Callable[[], Awaitable[None]]):
        """Add cleanup handler"""
        self._cleanup_handlers.append(handler)


# Decorator functions


def async_retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff_factor: float = 2.0,
    exceptions: Tuple[type, ...] = (Exception,),
) -> Callable[[F], F]:
    """Async retry decorator with exponential backoff"""
    config = RetryConfig(
        max_attempts=max_attempts,
        delay=delay,
        backoff_factor=backoff_factor,
        exceptions=exceptions,
    )
    retry_handler = AsyncRetry(config)

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await retry_handler(func, *args, **kwargs)

        return wrapper

    return decorator


def async_timeout(timeout: float) -> Callable[[F], F]:
    """Async timeout decorator"""

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await asyncio.wait_for(func(*args, **kwargs), timeout)

        return wrapper

    return decorator


def async_circuit_breaker(
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
    expected_exception: type = Exception,
) -> Callable[[F], F]:
    """Async circuit breaker decorator"""
    config = CircuitBreakerConfig(
        failure_threshold=failure_threshold,
        recovery_timeout=recovery_timeout,
        expected_exception=expected_exception,
    )
    circuit_breaker = AsyncCircuitBreaker(config)

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await circuit_breaker(func, *args, **kwargs)

        return wrapper

    return decorator


def async_semaphore_limit(
    max_concurrent: int = 10, timeout: Optional[float] = None
) -> Callable[[F], F]:
    """Async semaphore decorator for limiting concurrent executions"""
    config = SemaphoreConfig(max_concurrent=max_concurrent, timeout=timeout)
    semaphore = AsyncSemaphore(config)

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            async with semaphore.acquire():
                return await func(*args, **kwargs)

        return wrapper

    return decorator


# Utility functions


async def async_gather_with_concurrency(
    awaitables: List[Awaitable[T]], max_concurrency: int = 10
) -> List[T]:
    """Gather awaitables with concurrency limit"""
    semaphore = asyncio.Semaphore(max_concurrency)

    async def run_with_semaphore(awaitable):
        async with semaphore:
            return await awaitable

    limited_awaitables = [run_with_semaphore(aw) for aw in awaitables]
    return await asyncio.gather(*limited_awaitables)


async def async_rate_limit(
    calls_per_second: float, func: Callable[..., Awaitable[T]], *args, **kwargs
) -> T:
    """Simple rate limiting for async functions"""
    if not hasattr(async_rate_limit, "_last_call_times"):
        async_rate_limit._last_call_times = {}

    func_key = id(func)
    current_time = time.time()
    min_interval = 1.0 / calls_per_second

    if func_key in async_rate_limit._last_call_times:
        time_since_last = current_time - async_rate_limit._last_call_times[func_key]
        if time_since_last < min_interval:
            await asyncio.sleep(min_interval - time_since_last)

    async_rate_limit._last_call_times[func_key] = time.time()
    return await func(*args, **kwargs)


async def async_batch_processor(
    items: List[T],
    processor: Callable[[List[T]], Awaitable[Any]],
    batch_size: int = 100,
    max_concurrent_batches: int = 5,
) -> List[Any]:
    """Process items in batches with concurrency control"""
    # Split items into batches
    batches = [items[i : i + batch_size] for i in range(0, len(items), batch_size)]

    # Process batches with concurrency limit
    return await async_gather_with_concurrency(
        [processor(batch) for batch in batches], max_concurrency=max_concurrent_batches
    )
