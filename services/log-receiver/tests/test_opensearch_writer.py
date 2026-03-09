from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytest.importorskip(
    "opensearchpy", reason="opensearch-py not installed (install service deps to run)"
)

from ocsf.schema import OCSFEvent
from writers.opensearch_writer import OpenSearchWriter


def make_event() -> OCSFEvent:
    return OCSFEvent(
        class_uid=3002,
        class_name="authentication",
        time=datetime.now(tz=timezone.utc),
        severity_id=1,
        status_id=1,
        message="test event",
        metadata={"version": "1.3.0"},
        raw_data={},
    )


@pytest.mark.asyncio
async def test_write_batch_calls_bulk():
    writer = OpenSearchWriter("http://localhost:9200", retention_days=90)
    with patch(
        "writers.opensearch_writer.helpers.async_bulk", new_callable=AsyncMock
    ) as mock_bulk:
        mock_bulk.return_value = (2, [])
        count = await writer.write_batch([make_event(), make_event()])
    assert count == 2
    mock_bulk.assert_called_once()


@pytest.mark.asyncio
async def test_write_batch_empty():
    writer = OpenSearchWriter("http://localhost:9200", retention_days=90)
    with patch(
        "writers.opensearch_writer.helpers.async_bulk", new_callable=AsyncMock
    ) as mock_bulk:
        mock_bulk.return_value = (0, [])
        count = await writer.write_batch([])
    assert count == 0


@pytest.mark.asyncio
async def test_ensure_ism_policy_handles_error():
    """ISM policy errors are caught and logged, not raised."""
    writer = OpenSearchWriter("http://localhost:9200", retention_days=90)
    with patch.object(
        writer._client.plugins, "index_management", create=True
    ) as mock_im:
        mock_im.put_policy = AsyncMock(side_effect=Exception("connection refused"))
        # Should not raise
        await writer.ensure_ism_policy()
