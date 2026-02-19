"""
Cross-Service Message Queue System for SkausWatch

Provides async message queue system for inter-service communication with
Redis backend, routing, retry logic, and dead letter queues.
"""

import asyncio
import json
import logging
import pickle
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union
from uuid import uuid4

# Redis imports (conditional)
try:
    import redis.asyncio as aioredis

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    aioredis = None

from .async_utils import async_retry, async_timeout
from .cache_manager import CacheConfig, CacheManager
from .connection_pool import ConnectionPoolManager, PoolConfig

logger = logging.getLogger(__name__)


class MessagePriority(Enum):
    """Message priority levels"""

    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


class MessageStatus(Enum):
    """Message status"""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


@dataclass
class Message:
    """Message structure"""

    message_id: str
    service: str  # Source service
    destination: str  # Target service or queue
    message_type: str
    payload: Dict[str, Any]
    priority: MessagePriority = MessagePriority.NORMAL
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    correlation_id: Optional[str] = None
    reply_to: Optional[str] = None
    headers: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "service": self.service,
            "destination": self.destination,
            "message_type": self.message_type,
            "payload": self.payload,
            "priority": self.priority.value,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "correlation_id": self.correlation_id,
            "reply_to": self.reply_to,
            "headers": self.headers,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Message":
        return cls(
            message_id=data["message_id"],
            service=data["service"],
            destination=data["destination"],
            message_type=data["message_type"],
            payload=data["payload"],
            priority=MessagePriority(data["priority"]),
            retry_count=data["retry_count"],
            max_retries=data["max_retries"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data["expires_at"]
                else None
            ),
            correlation_id=data.get("correlation_id"),
            reply_to=data.get("reply_to"),
            headers=data.get("headers", {}),
        )


@dataclass
class MessageHandler:
    """Message handler configuration"""

    message_type: str
    handler_func: Callable
    service: str
    max_concurrent: int = 5
    timeout: float = 30.0
    auto_ack: bool = True


class BaseMessageQueue(ABC):
    """Base message queue interface"""

    @abstractmethod
    async def publish(self, message: Message) -> bool:
        """Publish message to queue"""
        pass

    @abstractmethod
    async def subscribe(self, queue_name: str, handler: Callable) -> None:
        """Subscribe to queue with handler"""
        pass

    @abstractmethod
    async def ack(self, message_id: str) -> bool:
        """Acknowledge message processing"""
        pass

    @abstractmethod
    async def nack(self, message_id: str, retry: bool = True) -> bool:
        """Negative acknowledge message"""
        pass


class RedisMessageQueue(BaseMessageQueue):
    """Redis-based message queue implementation"""

    def __init__(self, redis_url: str, config: Dict[str, Any]):
        self.redis_url = redis_url
        self.config = config
        self.redis_client: Optional[aioredis.Redis] = None

        # Queue configurations
        self.queue_prefix = config.get("queue_prefix", "skauswatch:queue")
        self.processing_prefix = config.get(
            "processing_prefix", "skauswatch:processing"
        )
        self.dead_letter_prefix = config.get("dead_letter_prefix", "skauswatch:dlq")

        # Message handlers
        self.handlers: Dict[str, List[MessageHandler]] = {}
        self.handler_tasks: List[asyncio.Task] = []

        # Metrics
        self.metrics = {
            "messages_published": 0,
            "messages_consumed": 0,
            "messages_failed": 0,
            "messages_retried": 0,
            "messages_dead_lettered": 0,
            "active_consumers": 0,
        }

        self.running = False

    async def initialize(self):
        """Initialize Redis connection"""
        if not HAS_REDIS:
            raise RuntimeError("redis package required for RedisMessageQueue")

        self.redis_client = aioredis.from_url(
            self.redis_url, decode_responses=True, retry_on_timeout=True
        )

        # Test connection
        await self.redis_client.ping()
        logger.info("Redis message queue initialized")

    async def close(self):
        """Close Redis connection"""
        self.running = False

        # Cancel handler tasks
        for task in self.handler_tasks:
            task.cancel()

        if self.handler_tasks:
            await asyncio.gather(*self.handler_tasks, return_exceptions=True)

        if self.redis_client:
            await self.redis_client.close()

    async def publish(self, message: Message) -> bool:
        """Publish message to Redis queue"""
        try:
            queue_key = f"{self.queue_prefix}:{message.destination}"

            # Serialize message
            message_data = json.dumps(message.to_dict())

            # Add to priority queue (using sorted set with priority as score)
            score = message.priority.value * 1000000 + int(time.time())

            await self.redis_client.zadd(queue_key, {message_data: score})

            # Set message expiration if specified
            if message.expires_at:
                expire_key = f"{queue_key}:expire:{message.message_id}"
                ttl = int((message.expires_at - datetime.utcnow()).total_seconds())
                if ttl > 0:
                    await self.redis_client.setex(expire_key, ttl, "1")

            self.metrics["messages_published"] += 1

            logger.debug(
                f"Published message {message.message_id} to {message.destination}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to publish message: {e}")
            return False

    async def subscribe(self, queue_name: str, handler: MessageHandler) -> None:
        """Subscribe to queue with handler"""
        if queue_name not in self.handlers:
            self.handlers[queue_name] = []

        self.handlers[queue_name].append(handler)

        # Start consumer task
        task = asyncio.create_task(self._consumer_loop(queue_name, handler))
        self.handler_tasks.append(task)

        logger.info(
            f"Subscribed to queue {queue_name} with handler for {handler.message_type}"
        )

    async def _consumer_loop(self, queue_name: str, handler: MessageHandler):
        """Consumer loop for processing messages"""
        queue_key = f"{self.queue_prefix}:{queue_name}"
        processing_key = f"{self.processing_prefix}:{queue_name}"

        self.running = True
        semaphore = asyncio.Semaphore(handler.max_concurrent)

        logger.info(f"Consumer loop started for {queue_name}")

        while self.running:
            try:
                # Get message from priority queue (highest priority first)
                result = await self.redis_client.zpopmax(queue_key, 1)

                if not result:
                    await asyncio.sleep(0.1)
                    continue

                message_data, score = result[0]

                try:
                    message_dict = json.loads(message_data)
                    message = Message.from_dict(message_dict)
                except Exception as e:
                    logger.error(f"Failed to deserialize message: {e}")
                    continue

                # Check if message expired
                if self._is_message_expired(message):
                    logger.debug(f"Message {message.message_id} expired, skipping")
                    continue

                # Check if message type matches handler
                if message.message_type != handler.message_type:
                    # Put back in queue for other handlers
                    await self.redis_client.zadd(queue_key, {message_data: score})
                    continue

                # Process message with concurrency control
                async with semaphore:
                    task = asyncio.create_task(
                        self._process_message(message, handler, processing_key)
                    )

            except Exception as e:
                logger.error(f"Consumer loop error for {queue_name}: {e}")
                await asyncio.sleep(1.0)

        logger.info(f"Consumer loop stopped for {queue_name}")

    async def _process_message(
        self, message: Message, handler: MessageHandler, processing_key: str
    ):
        """Process individual message"""
        start_time = time.time()

        try:
            # Add to processing set
            processing_data = {
                **message.to_dict(),
                "processing_started": datetime.utcnow().isoformat(),
                "handler_service": handler.service,
            }

            await self.redis_client.hset(
                processing_key, message.message_id, json.dumps(processing_data)
            )

            # Set processing timeout
            await self.redis_client.expire(
                f"{processing_key}:{message.message_id}", int(handler.timeout)
            )

            # Execute handler with timeout
            try:
                await asyncio.wait_for(
                    handler.handler_func(message), timeout=handler.timeout
                )

                # Acknowledge message if auto_ack is enabled
                if handler.auto_ack:
                    await self.ack(message.message_id)

                self.metrics["messages_consumed"] += 1

                processing_time = time.time() - start_time
                logger.debug(
                    f"Processed message {message.message_id} in {processing_time:.2f}s"
                )

            except asyncio.TimeoutError:
                logger.error(f"Message {message.message_id} processing timeout")
                await self.nack(message.message_id, retry=True)

            except Exception as e:
                logger.error(f"Message {message.message_id} processing failed: {e}")
                await self.nack(message.message_id, retry=True)

        except Exception as e:
            logger.error(f"Error in message processing setup: {e}")
            self.metrics["messages_failed"] += 1

    def _is_message_expired(self, message: Message) -> bool:
        """Check if message has expired"""
        if message.expires_at is None:
            return False
        return datetime.utcnow() > message.expires_at

    async def ack(self, message_id: str) -> bool:
        """Acknowledge message processing"""
        try:
            # Remove from processing sets
            for queue_name in self.handlers.keys():
                processing_key = f"{self.processing_prefix}:{queue_name}"
                await self.redis_client.hdel(processing_key, message_id)

            logger.debug(f"Acknowledged message {message_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to ack message {message_id}: {e}")
            return False

    async def nack(self, message_id: str, retry: bool = True) -> bool:
        """Negative acknowledge message"""
        try:
            # Find message in processing sets
            message_data = None
            queue_name = None

            for qname in self.handlers.keys():
                processing_key = f"{self.processing_prefix}:{qname}"
                data = await self.redis_client.hget(processing_key, message_id)
                if data:
                    message_data = json.loads(data)
                    queue_name = qname
                    break

            if not message_data:
                logger.warning(f"Message {message_id} not found in processing sets")
                return False

            message = Message.from_dict(message_data)

            # Remove from processing
            processing_key = f"{self.processing_prefix}:{queue_name}"
            await self.redis_client.hdel(processing_key, message_id)

            if retry and message.retry_count < message.max_retries:
                # Retry message
                message.retry_count += 1
                await self.publish(message)
                self.metrics["messages_retried"] += 1
                logger.debug(
                    f"Retrying message {message_id} (attempt {message.retry_count})"
                )
            else:
                # Send to dead letter queue
                await self._send_to_dead_letter(message, queue_name)
                self.metrics["messages_dead_lettered"] += 1
                logger.warning(f"Message {message_id} sent to dead letter queue")

            return True

        except Exception as e:
            logger.error(f"Failed to nack message {message_id}: {e}")
            return False

    async def _send_to_dead_letter(self, message: Message, queue_name: str):
        """Send message to dead letter queue"""
        dlq_key = f"{self.dead_letter_prefix}:{queue_name}"

        dlq_data = {
            **message.to_dict(),
            "dead_lettered_at": datetime.utcnow().isoformat(),
            "final_retry_count": message.retry_count,
        }

        await self.redis_client.lpush(dlq_key, json.dumps(dlq_data))

    async def get_queue_stats(self, queue_name: str) -> Dict[str, Any]:
        """Get queue statistics"""
        queue_key = f"{self.queue_prefix}:{queue_name}"
        processing_key = f"{self.processing_prefix}:{queue_name}"
        dlq_key = f"{self.dead_letter_prefix}:{queue_name}"

        stats = {
            "queue_size": await self.redis_client.zcard(queue_key),
            "processing_count": await self.redis_client.hlen(processing_key),
            "dead_letter_count": await self.redis_client.llen(dlq_key),
            "handlers_count": len(self.handlers.get(queue_name, [])),
            **self.metrics,
        }

        return stats


class MessageRouter:
    """Message routing and service discovery"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.routes: Dict[str, str] = {}  # service -> queue mapping
        self.service_registry: Dict[str, Dict[str, Any]] = {}

    def register_service(
        self,
        service_name: str,
        queue_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Register service with router"""
        self.routes[service_name] = queue_name
        self.service_registry[service_name] = {
            "queue_name": queue_name,
            "registered_at": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
        }

        logger.info(f"Registered service {service_name} -> {queue_name}")

    def get_route(self, service_name: str) -> Optional[str]:
        """Get queue name for service"""
        return self.routes.get(service_name)

    def list_services(self) -> Dict[str, Dict[str, Any]]:
        """List registered services"""
        return self.service_registry.copy()


class MessageQueueManager:
    """Central message queue management"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.queue_impl: Optional[BaseMessageQueue] = None
        self.router = MessageRouter(config.get("router", {}))
        self.cache_manager: Optional[CacheManager] = None

        # Request-response tracking
        self.pending_requests: Dict[str, asyncio.Future] = {}

    async def initialize(self):
        """Initialize message queue system"""
        # Initialize queue implementation
        if self.config.get("backend") == "redis":
            redis_config = self.config.get("redis", {})
            redis_url = redis_config.get("url", "redis://localhost:6379")

            self.queue_impl = RedisMessageQueue(redis_url, redis_config)
            await self.queue_impl.initialize()
        else:
            raise ValueError("Only Redis backend is currently supported")

        # Initialize caching for message deduplication
        self.cache_manager = CacheManager()
        cache_config = CacheConfig(
            max_size=10000, default_ttl=300.0, eviction_policy="lru"  # 5 minutes
        )
        self.cache_manager.create_memory_cache("message_dedup", cache_config)

        # Register built-in services
        self._register_builtin_services()

        logger.info("Message queue manager initialized")

    async def close(self):
        """Close message queue system"""
        if self.queue_impl:
            await self.queue_impl.close()
        if self.cache_manager:
            await self.cache_manager.close_all()

    def _register_builtin_services(self):
        """Register built-in SkausWatch services"""
        services = {
            "manager": "manager.queue",
            "pki-server": "pki.queue",
            "ssh-ca": "ssh-ca.queue",
            "aaa-monitor": "aaa-monitor.queue",
        }

        for service, queue in services.items():
            self.router.register_service(service, queue)

    @async_retry(max_attempts=3, delay=1.0)
    async def publish(
        self,
        destination: str,
        message_type: str,
        payload: Dict[str, Any],
        source_service: str = "unknown",
        priority: MessagePriority = MessagePriority.NORMAL,
        correlation_id: Optional[str] = None,
        reply_to: Optional[str] = None,
        expires_in: Optional[timedelta] = None,
    ) -> str:
        """Publish message to destination service"""

        # Resolve destination to queue
        queue_name = self.router.get_route(destination)
        if not queue_name:
            queue_name = destination  # Use destination as queue name directly

        # Create message
        message_id = str(uuid4())
        message = Message(
            message_id=message_id,
            service=source_service,
            destination=queue_name,
            message_type=message_type,
            payload=payload,
            priority=priority,
            correlation_id=correlation_id,
            reply_to=reply_to,
            expires_at=datetime.utcnow() + expires_in if expires_in else None,
        )

        # Check for duplicate messages
        dedup_key = f"{source_service}:{message_type}:{hash(str(payload))}"
        cache = self.cache_manager.get_cache("message_dedup")

        if cache:
            if await cache.exists(dedup_key):
                logger.debug(f"Duplicate message detected, skipping: {dedup_key}")
                return message_id
            await cache.set(dedup_key, message_id, ttl=30.0)  # 30 second dedup window

        # Publish message
        success = await self.queue_impl.publish(message)
        if not success:
            raise Exception(f"Failed to publish message to {destination}")

        logger.debug(f"Published message {message_id} to {destination}")
        return message_id

    async def subscribe(
        self,
        queue_name: str,
        message_type: str,
        handler_func: Callable,
        service_name: str = "unknown",
        max_concurrent: int = 5,
        timeout: float = 30.0,
        auto_ack: bool = True,
    ):
        """Subscribe to messages of specific type"""

        handler = MessageHandler(
            message_type=message_type,
            handler_func=handler_func,
            service=service_name,
            max_concurrent=max_concurrent,
            timeout=timeout,
            auto_ack=auto_ack,
        )

        await self.queue_impl.subscribe(queue_name, handler)

        logger.info(f"Subscribed {service_name} to {queue_name} for {message_type}")

    async def request(
        self,
        destination: str,
        message_type: str,
        payload: Dict[str, Any],
        source_service: str = "unknown",
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """Send request and wait for response"""

        # Generate correlation ID and reply queue
        correlation_id = str(uuid4())
        reply_queue = f"{source_service}.replies"

        # Set up response handler
        response_future = asyncio.Future()
        self.pending_requests[correlation_id] = response_future

        # Subscribe to reply queue if not already done
        await self.subscribe(
            reply_queue,
            "response",
            self._handle_response,
            source_service,
            auto_ack=True,
        )

        try:
            # Send request
            await self.publish(
                destination=destination,
                message_type=message_type,
                payload=payload,
                source_service=source_service,
                correlation_id=correlation_id,
                reply_to=reply_queue,
                priority=MessagePriority.HIGH,
            )

            # Wait for response
            response = await asyncio.wait_for(response_future, timeout=timeout)
            return response

        finally:
            # Cleanup
            self.pending_requests.pop(correlation_id, None)

    async def reply(
        self,
        original_message: Message,
        response_payload: Dict[str, Any],
        source_service: str = "unknown",
    ):
        """Send reply to request"""

        if not original_message.reply_to or not original_message.correlation_id:
            logger.warning("Cannot reply to message without reply_to or correlation_id")
            return

        await self.publish(
            destination=original_message.reply_to,
            message_type="response",
            payload=response_payload,
            source_service=source_service,
            correlation_id=original_message.correlation_id,
            priority=MessagePriority.HIGH,
        )

    async def _handle_response(self, message: Message):
        """Handle response messages"""
        if not message.correlation_id:
            logger.warning("Received response without correlation_id")
            return

        future = self.pending_requests.get(message.correlation_id)
        if future and not future.done():
            future.set_result(message.payload)

    async def get_stats(self) -> Dict[str, Any]:
        """Get message queue statistics"""
        stats = {
            "services_registered": len(self.router.service_registry),
            "services": self.router.list_services(),
            "pending_requests": len(self.pending_requests),
        }

        # Add queue-specific stats if available
        if hasattr(self.queue_impl, "metrics"):
            stats.update(self.queue_impl.metrics)

        return stats


# Global message queue manager
_global_message_queue: Optional[MessageQueueManager] = None


def get_global_message_queue() -> MessageQueueManager:
    """Get global message queue manager"""
    if _global_message_queue is None:
        raise RuntimeError("Message queue manager not initialized")
    return _global_message_queue


async def initialize_global_message_queue(
    config: Dict[str, Any],
) -> MessageQueueManager:
    """Initialize global message queue manager"""
    global _global_message_queue
    _global_message_queue = MessageQueueManager(config)
    await _global_message_queue.initialize()
    return _global_message_queue


async def cleanup_global_message_queue():
    """Cleanup global message queue manager"""
    global _global_message_queue
    if _global_message_queue is not None:
        await _global_message_queue.close()
        _global_message_queue = None
