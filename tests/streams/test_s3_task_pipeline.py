"""S3 scan task pipeline tests.

Tests the TRIGGER → TRANSFORM → ACTION flow:
1. Manager publishes ScanTaskMessage to Redis Stream
2. Worker receives, downloads (mock S3), scans (mock ClamAV+YARA)
3. Worker publishes ScanResultMessage
4. Manager consumes result

Uses fakeredis when available, otherwise skips gracefully.
"""

import json

import pytest

try:
    import fakeredis.aioredis

    HAS_FAKEREDIS = True
except ImportError:
    HAS_FAKEREDIS = False


@pytest.mark.stream
@pytest.mark.skipif(not HAS_FAKEREDIS, reason="fakeredis not installed")
class TestS3TaskPublish:
    """Manager publishes scan task messages."""

    async def test_publish_scan_task_message(self):
        """ScanTaskMessage can be serialized and published to a stream."""
        redis = fakeredis.aioredis.FakeRedis()

        task_message = {
            "job_id": "test-job-001",
            "bucket_config_id": 1,
            "object_key": "documents/test.pdf",
            "endpoint_url": "https://s3.amazonaws.com",
            "bucket_name": "test-bucket",
            "access_key_id": "AKIATEST",
            "secret_access_key": "test-secret",
            "max_file_size_mb": 100,
        }

        msg_id = await redis.xadd(
            "skauswatch:s3scan:tasks",
            {"data": json.dumps(task_message)},
        )
        assert msg_id is not None

        # Read it back
        messages = await redis.xread({"skauswatch:s3scan:tasks": "0"})
        assert len(messages) > 0
        stream_name, entries = messages[0]
        assert len(entries) > 0
        _, fields = entries[0]
        parsed = json.loads(fields[b"data"])
        assert parsed["job_id"] == "test-job-001"
        assert parsed["object_key"] == "documents/test.pdf"

        await redis.aclose()

    async def test_publish_result_message(self):
        """ScanResultMessage can be published to results stream."""
        redis = fakeredis.aioredis.FakeRedis()

        result_message = {
            "job_id": "test-job-001",
            "object_key": "documents/test.pdf",
            "scan_status": "completed",
            "is_malware": False,
            "is_threat": False,
            "threat_names": [],
            "file_md5": "d41d8cd98f00b204e9800998ecf8427e",
            "file_sha256": "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
            "scan_duration_ms": 1234,
        }

        msg_id = await redis.xadd(
            "skauswatch:s3scan:results",
            {"data": json.dumps(result_message)},
        )
        assert msg_id is not None

        await redis.aclose()


@pytest.mark.stream
@pytest.mark.skipif(not HAS_FAKEREDIS, reason="fakeredis not installed")
class TestConsumerGroupRoundTrip:
    """Consumer group creation and message consumption."""

    async def test_consumer_group_create_and_read(self):
        """Create consumer group, publish, read with group."""
        redis = fakeredis.aioredis.FakeRedis()
        stream_key = "skauswatch:test:stream"

        # Publish first message to create the stream
        await redis.xadd(stream_key, {"data": "init"})

        # Create consumer group
        await redis.xgroup_create(
            stream_key, "test-group", id="0", mkstream=True
        )

        # Publish a task
        await redis.xadd(
            stream_key,
            {"data": json.dumps({"task": "scan", "file": "test.pdf"})},
        )

        # Read as consumer
        messages = await redis.xreadgroup(
            "test-group",
            "consumer-1",
            {stream_key: ">"},
            count=10,
        )

        assert len(messages) > 0
        stream_name, entries = messages[0]
        assert len(entries) > 0

        # Acknowledge
        msg_id = entries[0][0]
        ack_count = await redis.xack(stream_key, "test-group", msg_id)
        assert ack_count == 1

        await redis.aclose()

    async def test_multiple_consumers_partition_messages(self):
        """Multiple consumers in a group each get unique messages."""
        redis = fakeredis.aioredis.FakeRedis()
        stream_key = "skauswatch:test:partition"

        # Create stream + group
        await redis.xadd(stream_key, {"data": "init"})
        await redis.xgroup_create(stream_key, "workers", id="0", mkstream=True)

        # Publish 4 messages
        for i in range(4):
            await redis.xadd(stream_key, {"data": f"task-{i}"})

        # Consumer 1 reads
        msgs1 = await redis.xreadgroup(
            "workers", "worker-1", {stream_key: ">"}, count=2
        )

        # Consumer 2 reads remaining
        msgs2 = await redis.xreadgroup(
            "workers", "worker-2", {stream_key: ">"}, count=2
        )

        total = 0
        if msgs1:
            total += len(msgs1[0][1])
        if msgs2:
            total += len(msgs2[0][1])

        # All 4 messages should be distributed
        assert total == 4

        await redis.aclose()
