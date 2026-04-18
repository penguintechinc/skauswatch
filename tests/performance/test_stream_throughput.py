"""
Redis Stream throughput tests.

Tests publish/consume throughput to ensure the stream
infrastructure can handle production load.

All tests use fakeredis to avoid network overhead and focus
solely on serialisation / deserialisation performance.

Marked as @performance and @slow — not run in pre-commit.
"""
import pytest
import time
import json

pytestmark = [pytest.mark.performance, pytest.mark.slow]

try:
    import fakeredis
    import fakeredis.aioredis

    HAS_FAKEREDIS = True
except ImportError:
    HAS_FAKEREDIS = False

# ---------------------------------------------------------------------------
# Shared stream helpers
# ---------------------------------------------------------------------------

STREAM_KEY = "skauswatch:perf:throughput"
MESSAGE_COUNT = 1_000
MAX_PUBLISH_SECONDS = 5.0   # 1 000 publishes must complete within 5 s
MAX_CONSUME_SECONDS = 5.0   # 1 000 reads must complete within 5 s
MAX_ROUNDTRIP_MS = 100.0    # Single publish→read roundtrip must be < 100 ms


def _make_scan_task_payload(index: int) -> dict:
    """Return a realistic ScanTaskMessage dict."""
    return {
        "job_id": f"perf-job-{index:06d}",
        "bucket_config_id": (index % 10) + 1,
        "object_key": f"documents/perf-test-file-{index:06d}.pdf",
        "endpoint_url": "https://s3.amazonaws.com",
        "bucket_name": "perf-test-bucket",
        "access_key_id": "AKIATEST0000000PERF",
        "secret_access_key": "perf-secret-key-value",
        "max_file_size_mb": 100,
        "scan_type": "full",
        "priority": index % 3,
    }


# ---------------------------------------------------------------------------
# Class 1: Publish throughput
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_FAKEREDIS, reason="fakeredis not installed")
class TestStreamPublishThroughput:
    """Publish 1 000 messages and assert throughput is acceptable."""

    async def test_publish_1000_messages_within_time_budget(self):
        """Publishing 1 000 JSON messages must complete in < 5 seconds."""
        redis = fakeredis.aioredis.FakeRedis()

        start = time.perf_counter()
        for i in range(MESSAGE_COUNT):
            payload = _make_scan_task_payload(i)
            await redis.xadd(STREAM_KEY, {"data": json.dumps(payload)})
        elapsed = time.perf_counter() - start

        await redis.aclose()

        assert elapsed < MAX_PUBLISH_SECONDS, (
            f"Published {MESSAGE_COUNT} messages in {elapsed:.3f}s "
            f"(budget: {MAX_PUBLISH_SECONDS}s)"
        )

    async def test_publish_throughput_rate(self):
        """Verify publish rate exceeds 200 messages/second with fakeredis."""
        redis = fakeredis.aioredis.FakeRedis()

        start = time.perf_counter()
        for i in range(MESSAGE_COUNT):
            payload = _make_scan_task_payload(i)
            await redis.xadd(STREAM_KEY, {"data": json.dumps(payload)})
        elapsed = time.perf_counter() - start

        await redis.aclose()

        rate = MESSAGE_COUNT / elapsed
        assert rate > 200, f"Publish rate {rate:.0f} msg/s is below 200 msg/s"

    async def test_stream_length_after_publish(self):
        """Stream length equals MESSAGE_COUNT after publishing."""
        redis = fakeredis.aioredis.FakeRedis()

        for i in range(MESSAGE_COUNT):
            payload = _make_scan_task_payload(i)
            await redis.xadd(STREAM_KEY, {"data": json.dumps(payload)})

        length = await redis.xlen(STREAM_KEY)
        await redis.aclose()

        assert length == MESSAGE_COUNT

    async def test_publish_with_varying_payload_sizes(self):
        """Serialisation overhead is acceptable even with larger payloads."""
        redis = fakeredis.aioredis.FakeRedis()

        start = time.perf_counter()
        for i in range(MESSAGE_COUNT):
            payload = _make_scan_task_payload(i)
            # Simulate threat intel enrichment adding ~500 bytes
            payload["ti_enrichment"] = {
                "ioc_hits": [f"ioc-{j}" for j in range(5)],
                "threat_score": round(i / MESSAGE_COUNT, 4),
                "context": "A" * 200,
            }
            await redis.xadd(STREAM_KEY, {"data": json.dumps(payload)})
        elapsed = time.perf_counter() - start

        await redis.aclose()

        # Allow 2x budget for larger payloads
        assert elapsed < MAX_PUBLISH_SECONDS * 2, (
            f"Published {MESSAGE_COUNT} large messages in {elapsed:.3f}s "
            f"(budget: {MAX_PUBLISH_SECONDS * 2}s)"
        )


# ---------------------------------------------------------------------------
# Class 2: Consume throughput
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_FAKEREDIS, reason="fakeredis not installed")
class TestStreamConsumeThroughput:
    """Read 1 000 messages from a pre-populated stream within the time budget."""

    async def _populate_stream(self, redis, key: str, count: int = MESSAGE_COUNT):
        """Helper: fill a stream with count messages."""
        for i in range(count):
            payload = _make_scan_task_payload(i)
            await redis.xadd(key, {"data": json.dumps(payload)})

    async def test_read_1000_messages_within_time_budget(self):
        """Reading all 1 000 messages must complete in < 5 seconds."""
        redis = fakeredis.aioredis.FakeRedis()
        await self._populate_stream(redis, STREAM_KEY)

        start = time.perf_counter()
        messages = await redis.xread({STREAM_KEY: "0"}, count=MESSAGE_COUNT)
        elapsed = time.perf_counter() - start

        await redis.aclose()

        assert elapsed < MAX_CONSUME_SECONDS, (
            f"Read {MESSAGE_COUNT} messages in {elapsed:.3f}s "
            f"(budget: {MAX_CONSUME_SECONDS}s)"
        )

    async def test_consume_and_deserialize_all_messages(self):
        """Every consumed message can be deserialised from JSON."""
        redis = fakeredis.aioredis.FakeRedis()
        await self._populate_stream(redis, STREAM_KEY)

        messages = await redis.xread({STREAM_KEY: "0"}, count=MESSAGE_COUNT)
        assert len(messages) > 0

        _, entries = messages[0]
        parsed_count = 0
        for _msg_id, fields in entries:
            parsed = json.loads(fields[b"data"])
            assert "job_id" in parsed
            assert "object_key" in parsed
            parsed_count += 1

        assert parsed_count == MESSAGE_COUNT

    async def test_consumer_group_read_throughput(self):
        """Consumer-group reads of 1 000 messages must complete in < 5 seconds."""
        redis = fakeredis.aioredis.FakeRedis()
        group_stream = "skauswatch:perf:group-consume"
        await self._populate_stream(redis, group_stream)

        await redis.xgroup_create(group_stream, "perf-group", id="0", mkstream=False)

        start = time.perf_counter()
        messages = await redis.xreadgroup(
            "perf-group",
            "consumer-1",
            {group_stream: ">"},
            count=MESSAGE_COUNT,
        )
        elapsed = time.perf_counter() - start

        await redis.aclose()

        assert elapsed < MAX_CONSUME_SECONDS, (
            f"Consumer group read {MESSAGE_COUNT} messages in {elapsed:.3f}s "
            f"(budget: {MAX_CONSUME_SECONDS}s)"
        )
        assert len(messages) > 0
        _, entries = messages[0]
        assert len(entries) == MESSAGE_COUNT

    async def test_batch_ack_throughput(self):
        """Acknowledging 1 000 messages via XACK must be fast."""
        redis = fakeredis.aioredis.FakeRedis()
        ack_stream = "skauswatch:perf:ack"
        await self._populate_stream(redis, ack_stream)

        await redis.xgroup_create(ack_stream, "ack-group", id="0", mkstream=False)

        messages = await redis.xreadgroup(
            "ack-group",
            "consumer-1",
            {ack_stream: ">"},
            count=MESSAGE_COUNT,
        )
        _, entries = messages[0]
        msg_ids = [msg_id for msg_id, _ in entries]

        start = time.perf_counter()
        ack_count = await redis.xack(ack_stream, "ack-group", *msg_ids)
        elapsed = time.perf_counter() - start

        await redis.aclose()

        assert ack_count == MESSAGE_COUNT
        assert elapsed < 1.0, (
            f"Batch XACK of {MESSAGE_COUNT} messages took {elapsed:.3f}s "
            "(budget: 1.0s)"
        )


# ---------------------------------------------------------------------------
# Class 3: Round-trip latency
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not HAS_FAKEREDIS, reason="fakeredis not installed")
class TestStreamRoundTrip:
    """Publish→consume round-trip latency for individual messages."""

    async def test_single_message_round_trip_latency(self):
        """Single publish→read round-trip must complete in < 100 ms."""
        redis = fakeredis.aioredis.FakeRedis()
        rt_stream = "skauswatch:perf:roundtrip"

        payload = _make_scan_task_payload(0)

        start = time.perf_counter()
        msg_id = await redis.xadd(rt_stream, {"data": json.dumps(payload)})
        messages = await redis.xread({rt_stream: "0"}, count=1)
        elapsed_ms = (time.perf_counter() - start) * 1000

        await redis.aclose()

        assert msg_id is not None
        assert len(messages) > 0
        assert elapsed_ms < MAX_ROUNDTRIP_MS, (
            f"Round-trip latency {elapsed_ms:.2f}ms exceeds {MAX_ROUNDTRIP_MS}ms"
        )

    async def test_round_trip_preserves_message_content(self):
        """The message read back from the stream is identical to what was published."""
        redis = fakeredis.aioredis.FakeRedis()
        rt_stream = "skauswatch:perf:content"

        original = _make_scan_task_payload(42)
        await redis.xadd(rt_stream, {"data": json.dumps(original)})

        messages = await redis.xread({rt_stream: "0"}, count=1)
        _, entries = messages[0]
        _, fields = entries[0]
        recovered = json.loads(fields[b"data"])

        await redis.aclose()

        assert recovered == original

    async def test_round_trip_with_consumer_group(self):
        """Publish→XREADGROUP→XACK round-trip must complete in < 100 ms."""
        redis = fakeredis.aioredis.FakeRedis()
        rt_stream = "skauswatch:perf:rt-group"

        payload = _make_scan_task_payload(1)
        await redis.xadd(rt_stream, {"data": json.dumps(payload)})
        await redis.xgroup_create(rt_stream, "rt-group", id="0", mkstream=False)

        start = time.perf_counter()
        messages = await redis.xreadgroup(
            "rt-group",
            "consumer-1",
            {rt_stream: ">"},
            count=1,
        )
        _, entries = messages[0]
        msg_id, fields = entries[0]
        json.loads(fields[b"data"])  # deserialise
        await redis.xack(rt_stream, "rt-group", msg_id)
        elapsed_ms = (time.perf_counter() - start) * 1000

        await redis.aclose()

        assert elapsed_ms < MAX_ROUNDTRIP_MS, (
            f"Consumer group round-trip {elapsed_ms:.2f}ms exceeds {MAX_ROUNDTRIP_MS}ms"
        )

    async def test_100_sequential_round_trips_p95_latency(self):
        """p95 of 100 sequential publish→read latencies must be < 50 ms."""
        redis = fakeredis.aioredis.FakeRedis()
        rt_stream = "skauswatch:perf:p95"

        latencies_ms = []
        for i in range(100):
            payload = _make_scan_task_payload(i)
            start = time.perf_counter()
            msg_id = await redis.xadd(
                rt_stream, {"data": json.dumps(payload)}, id="*"
            )
            messages = await redis.xread({rt_stream: b"0"}, count=1)
            elapsed_ms = (time.perf_counter() - start) * 1000
            latencies_ms.append(elapsed_ms)

        await redis.aclose()

        latencies_ms.sort()
        p95_index = int(len(latencies_ms) * 0.95)
        p95 = latencies_ms[p95_index]

        assert p95 < 50.0, (
            f"p95 round-trip latency {p95:.2f}ms exceeds 50ms"
        )
