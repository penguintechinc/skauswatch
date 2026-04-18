"""
Integration tests for Redis Streams.

Tests publish/consume round-trip, consumer groups,
acknowledgment, and error handling using real Redis
or fakeredis fallback.
"""

import json
import time
import uuid

import pytest

pytestmark = [pytest.mark.integration]


def _get_redis_client(redis_reachable):
    """Get a Redis client — real if available, fakeredis otherwise."""
    if redis_reachable:
        import redis

        return redis.Redis(host="localhost", port=6379, decode_responses=True)
    else:
        try:
            import fakeredis

            return fakeredis.FakeRedis(decode_responses=True)
        except ImportError:
            pytest.skip("Neither Redis nor fakeredis available")


class TestRedisStreamPublishConsume:
    """Test basic publish and consume on Redis Streams."""

    @pytest.fixture
    def redis_client(self, redis_reachable):
        """Provide Redis client (real or fake)."""
        client = _get_redis_client(redis_reachable)
        yield client
        client.close()

    @pytest.fixture
    def stream_key(self):
        """Generate unique stream key for test isolation."""
        return f"skauswatch:test:{uuid.uuid4().hex[:8]}"

    def test_publish_and_read(self, redis_client, stream_key):
        """Publish a message and read it back."""
        msg_id = redis_client.xadd(
            stream_key,
            {"type": "scan_task", "bucket_id": "1", "payload": "test"},
        )
        assert msg_id is not None

        messages = redis_client.xrange(stream_key, count=1)
        assert len(messages) == 1
        _, fields = messages[0]
        assert fields["type"] == "scan_task"
        assert fields["bucket_id"] == "1"

        # Cleanup
        redis_client.delete(stream_key)

    def test_publish_json_payload(self, redis_client, stream_key):
        """Publish a JSON-serialized payload."""
        payload = json.dumps({
            "scan_id": "scan-123",
            "bucket_config_id": 1,
            "object_key": "uploads/malware.exe",
            "timestamp": time.time(),
        })
        redis_client.xadd(stream_key, {"data": payload})

        messages = redis_client.xrange(stream_key)
        assert len(messages) == 1
        data = json.loads(messages[0][1]["data"])
        assert data["scan_id"] == "scan-123"

        redis_client.delete(stream_key)

    def test_publish_multiple_messages(self, redis_client, stream_key):
        """Publish and read multiple messages maintaining order."""
        for i in range(10):
            redis_client.xadd(stream_key, {"seq": str(i)})

        messages = redis_client.xrange(stream_key)
        assert len(messages) == 10

        for i, (_, fields) in enumerate(messages):
            assert fields["seq"] == str(i)

        redis_client.delete(stream_key)


class TestRedisStreamConsumerGroups:
    """Test consumer group functionality."""

    @pytest.fixture
    def redis_client(self, redis_reachable):
        """Provide Redis client."""
        client = _get_redis_client(redis_reachable)
        yield client
        client.close()

    @pytest.fixture
    def stream_key(self):
        return f"skauswatch:test:cg:{uuid.uuid4().hex[:8]}"

    def test_create_consumer_group(self, redis_client, stream_key):
        """Create a consumer group on a stream."""
        # Create stream first with initial message
        redis_client.xadd(stream_key, {"init": "true"})

        result = redis_client.xgroup_create(
            stream_key, "test-workers", id="0", mkstream=True
        )
        assert result is True

        redis_client.delete(stream_key)

    def test_consumer_group_read(self, redis_client, stream_key):
        """Read messages via consumer group."""
        redis_client.xadd(stream_key, {"task": "scan-1"})
        redis_client.xadd(stream_key, {"task": "scan-2"})
        redis_client.xgroup_create(stream_key, "workers", id="0")

        # Consumer reads pending messages
        messages = redis_client.xreadgroup(
            "workers", "worker-1", {stream_key: ">"}, count=10
        )
        assert len(messages) == 1  # One stream
        stream_msgs = messages[0][1]
        assert len(stream_msgs) == 2

        redis_client.delete(stream_key)

    def test_acknowledge_message(self, redis_client, stream_key):
        """Acknowledge processed message."""
        redis_client.xadd(stream_key, {"task": "scan-ack"})
        redis_client.xgroup_create(stream_key, "workers", id="0")

        messages = redis_client.xreadgroup(
            "workers", "worker-1", {stream_key: ">"}, count=1
        )
        msg_id = messages[0][1][0][0]

        ack_count = redis_client.xack(stream_key, "workers", msg_id)
        assert ack_count == 1

        redis_client.delete(stream_key)

    def test_multiple_consumers_no_duplicate(self, redis_client, stream_key):
        """Multiple consumers in same group don't get same message."""
        for i in range(4):
            redis_client.xadd(stream_key, {"task": f"scan-{i}"})
        redis_client.xgroup_create(stream_key, "workers", id="0")

        # Consumer 1 reads
        msgs_c1 = redis_client.xreadgroup(
            "workers", "consumer-1", {stream_key: ">"}, count=2
        )
        # Consumer 2 reads remaining
        msgs_c2 = redis_client.xreadgroup(
            "workers", "consumer-2", {stream_key: ">"}, count=2
        )

        c1_tasks = [m[1]["task"] for m in msgs_c1[0][1]]
        c2_tasks = [m[1]["task"] for m in msgs_c2[0][1]]

        # No overlap
        assert set(c1_tasks).isdisjoint(set(c2_tasks))
        assert len(c1_tasks) + len(c2_tasks) == 4

        redis_client.delete(stream_key)

    def test_pending_messages_after_crash(self, redis_client, stream_key):
        """Unacked messages remain pending for reprocessing."""
        redis_client.xadd(stream_key, {"task": "crash-test"})
        redis_client.xgroup_create(stream_key, "workers", id="0")

        # Read but don't ack (simulating crash)
        redis_client.xreadgroup(
            "workers", "crashed-worker", {stream_key: ">"}, count=1
        )

        # Check pending
        pending = redis_client.xpending(stream_key, "workers")
        assert pending["pending"] >= 1

        redis_client.delete(stream_key)


class TestRedisStreamThroughput:
    """Test stream throughput with bulk operations."""

    @pytest.fixture
    def redis_client(self, redis_reachable):
        client = _get_redis_client(redis_reachable)
        yield client
        client.close()

    @pytest.fixture
    def stream_key(self):
        return f"skauswatch:test:perf:{uuid.uuid4().hex[:8]}"

    @pytest.mark.slow
    def test_bulk_publish_throughput(self, redis_client, stream_key):
        """Publish 500 messages and verify all readable."""
        count = 500
        start = time.perf_counter()
        for i in range(count):
            redis_client.xadd(
                stream_key,
                {"seq": str(i), "data": f"payload-{i}"},
            )
        elapsed = time.perf_counter() - start

        # Verify all messages present
        messages = redis_client.xrange(stream_key)
        assert len(messages) == count

        # Should complete in reasonable time (even with fakeredis)
        assert elapsed < 30.0, f"Publishing {count} messages took {elapsed:.2f}s"

        redis_client.delete(stream_key)

    def test_stream_length_trimming(self, redis_client, stream_key):
        """Test MAXLEN trimming to prevent unbounded growth."""
        # Add more than maxlen
        for i in range(20):
            redis_client.xadd(stream_key, {"seq": str(i)}, maxlen=10)

        length = redis_client.xlen(stream_key)
        # Redis MAXLEN is approximate by default, should be close to 10
        assert length <= 15  # Allow some slack for approximate trimming

        redis_client.delete(stream_key)
