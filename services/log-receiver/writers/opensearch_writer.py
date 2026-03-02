from datetime import datetime, timezone

from opensearchpy import AsyncOpenSearch, helpers
from penguin_utils import get_logger

from ocsf.schema import OCSFEvent

logger = get_logger(__name__)

INDEX_PATTERN = "skauswatch-logs"


class OpenSearchWriter:
    def __init__(self, url: str, retention_days: int) -> None:
        self._client = AsyncOpenSearch(hosts=[url])
        self._retention_days = retention_days

    async def ensure_ism_policy(self) -> None:
        """Create/update ISM hot→warm→delete policy (idempotent)."""
        from ism.policy import build_ism_policy
        policy = build_ism_policy(self._retention_days)
        try:
            await self._client.plugins.index_management.put_policy(  # type: ignore[attr-defined]
                policy="skauswatch-logs-policy", body=policy
            )
            logger.info("ism_policy_applied", retention_days=self._retention_days)
        except Exception as exc:
            logger.warning("ism_policy_error", error=str(exc))

    async def write_batch(self, events: list[OCSFEvent]) -> int:
        """Bulk index events. Returns count indexed."""
        now = datetime.now(tz=timezone.utc)
        index = f"{INDEX_PATTERN}-{now.strftime('%Y.%m.%d')}"
        actions = [
            {"_index": index, "_source": e.to_dict()}
            for e in events
        ]
        success, _ = await helpers.async_bulk(self._client, actions, raise_on_error=False)
        logger.info("opensearch_indexed", index=index, count=success)
        return success

    async def close(self) -> None:
        await self._client.close()
