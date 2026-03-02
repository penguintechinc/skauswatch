import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import aiobotocore.session
import pyarrow as pa
import pyarrow.parquet as pq
from penguin_utils import get_logger

from ocsf.schema import OCSFEvent

logger = get_logger(__name__)


class ParquetWriter:
    """Writes OCSF events to S3-compatible storage as Parquet (Snappy compressed).

    S3 provider is fully configurable:
    - MinIO (self-hosted): S3_ENDPOINT_URL=http://minio:9000
    - AWS S3: S3_ENDPOINT_URL= (empty/unset)
    - GCP GCS (S3 interop): S3_ENDPOINT_URL=https://storage.googleapis.com
    - Cloudflare R2: S3_ENDPOINT_URL=https://<acct>.r2.cloudflarestorage.com
    """

    SCHEMA = pa.schema([
        ("class_uid", pa.int32()),
        ("class_name", pa.string()),
        ("time", pa.timestamp("us", tz="UTC")),
        ("severity_id", pa.int8()),
        ("status_id", pa.int8()),
        ("message", pa.string()),
        ("raw_data", pa.string()),   # JSON string
    ])

    def __init__(
        self,
        endpoint_url: str | None,
        region: str,
        access_key: str,
        secret_key: str,
        bucket: str,
    ) -> None:
        self._session = aiobotocore.session.get_session()
        self._endpoint_url = endpoint_url  # None = AWS S3
        self._region = region
        self._access_key = access_key
        self._secret_key = secret_key
        self._bucket = bucket

    async def write_batch(self, events: list[OCSFEvent]) -> str:
        """Serialize batch to Parquet and upload. Returns S3 key."""
        if not events:
            return ""

        now = datetime.now(tz=timezone.utc)
        first = events[0]
        partition = (
            f"ocsf_class={first.class_name}"
            f"/year={now.year}"
            f"/month={now.month:02d}"
            f"/day={now.day:02d}"
            f"/hour={now.hour:02d}"
        )
        key = f"{partition}/part-{uuid.uuid4()}.parquet"

        table = pa.table(
            {
                "class_uid": [e.class_uid for e in events],
                "class_name": [e.class_name for e in events],
                "time": pa.array([e.time for e in events], type=pa.timestamp("us", tz="UTC")),
                "severity_id": [e.severity_id for e in events],
                "status_id": [e.status_id for e in events],
                "message": [e.message for e in events],
                "raw_data": [json.dumps(e.raw_data) for e in events],
            },
            schema=self.SCHEMA,
        )

        buf = io.BytesIO()
        pq.write_table(table, buf, compression="snappy")
        buf.seek(0)

        kwargs: dict[str, Any] = {
            "region_name": self._region,
            "aws_access_key_id": self._access_key,
            "aws_secret_access_key": self._secret_key,
        }
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url

        async with self._session.create_client("s3", **kwargs) as client:
            await client.put_object(Bucket=self._bucket, Key=key, Body=buf.read())

        logger.info("parquet_uploaded", key=key, events=len(events))
        return key
