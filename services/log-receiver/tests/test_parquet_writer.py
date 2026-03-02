import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

pytest.importorskip("aiobotocore", reason="aiobotocore not installed (install service deps to run)")
pytest.importorskip("pyarrow", reason="pyarrow not installed (install service deps to run)")

from ocsf.schema import OCSFEvent
from writers.parquet_writer import ParquetWriter


def make_event(class_name: str = "authentication") -> OCSFEvent:
    return OCSFEvent(
        class_uid=3002,
        class_name=class_name,
        time=datetime.now(tz=timezone.utc),
        severity_id=1,
        status_id=1,
        message="test event",
        metadata={"version": "1.3.0"},
        raw_data={"message": "test"},
    )


def _mock_writer(endpoint_url=None):
    writer = ParquetWriter(
        endpoint_url=endpoint_url,
        region="us-east-1",
        access_key="test",
        secret_key="test",
        bucket="test-bucket",
    )
    mock_client = AsyncMock()
    mock_client.put_object = AsyncMock()
    mock_session = MagicMock()
    mock_session.create_client.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_session.create_client.return_value.__aexit__ = AsyncMock(return_value=False)
    writer._session = mock_session
    return writer, mock_client, mock_session


@pytest.mark.asyncio
async def test_write_batch_uploads_parquet():
    writer, mock_client, _ = _mock_writer("http://minio:9000")
    events = [make_event(), make_event()]
    key = await writer.write_batch(events)

    assert key.startswith("ocsf_class=authentication/")
    assert key.endswith(".parquet")
    mock_client.put_object.assert_called_once()


@pytest.mark.asyncio
async def test_write_batch_empty():
    writer = ParquetWriter(None, "us-east-1", "", "", "bucket")
    key = await writer.write_batch([])
    assert key == ""


@pytest.mark.asyncio
async def test_write_batch_aws_s3_no_endpoint():
    """When endpoint_url is None, aiobotocore uses AWS S3 directly."""
    writer, mock_client, mock_session = _mock_writer(None)
    await writer.write_batch([make_event()])

    # Verify no endpoint_url was passed (AWS S3 mode)
    call_kwargs = mock_session.create_client.call_args[1]
    assert "endpoint_url" not in call_kwargs
    mock_client.put_object.assert_called_once()


@pytest.mark.asyncio
async def test_write_batch_partition_path():
    """Verify Hive partition path format."""
    writer, _, _ = _mock_writer("http://minio:9000")
    events = [make_event("network_activity")]
    key = await writer.write_batch(events)
    assert "ocsf_class=network_activity" in key
    assert "/year=" in key
    assert "/month=" in key
    assert "/day=" in key
    assert "/hour=" in key


@pytest.mark.asyncio
async def test_write_batch_multiple_events():
    """All events in a batch are serialized into one file."""
    writer, mock_client, _ = _mock_writer("http://minio:9000")
    events = [make_event() for _ in range(100)]
    key = await writer.write_batch(events)
    assert key != ""
    # Only one put_object call for the whole batch
    assert mock_client.put_object.call_count == 1
