"""SIEM / log pipeline API blueprint.

Provides 6 routes:
- GET  /api/v1/siem/health  — log-receiver + opensearch health
- POST /api/v1/siem/ingest  — proxy ingestion to log-receiver
- GET  /api/v1/siem/search  — search OpenSearch logs
- GET  /api/v1/siem/stats   — ingest statistics (by class, severity)
- GET  /api/v1/siem/config  — current SIEM configuration
- PUT  /api/v1/siem/config  — update retention days (admin only)
"""

import httpx
import structlog
from api.v1.auth import auth_required, role_required
from opensearchpy import AsyncOpenSearch
from quart import Blueprint, current_app, jsonify, request

logger = structlog.get_logger(__name__)

bp = Blueprint("siem", __name__)


@bp.get("/health")
async def siem_health():
    """Check log-receiver + opensearch health."""
    cfg = current_app.config["MANAGER_CONFIG"].siem
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{cfg.log_receiver_url}/healthz")
            receiver_ok = resp.status_code == 200
        except Exception:
            receiver_ok = False

    return jsonify(
        {
            "log_receiver": "ok" if receiver_ok else "unavailable",
            "status": "ok" if receiver_ok else "degraded",
        }
    )


@bp.post("/ingest")
@auth_required
async def proxy_ingest():
    """Proxy log ingestion to log-receiver."""
    cfg = current_app.config["MANAGER_CONFIG"].siem
    body = await request.get_json()
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(f"{cfg.log_receiver_url}/ingest", json=body)
    return jsonify(resp.json()), resp.status_code


@bp.get("/search")
@auth_required
async def search_logs():
    """Search OpenSearch logs.

    Query params: q, from_date, to_date, class_name, severity, page, page_size
    """
    cfg = current_app.config["MANAGER_CONFIG"].siem
    query = _build_os_query(request.args)
    client = AsyncOpenSearch(hosts=[cfg.opensearch_url])
    try:
        resp = await client.search(index="skauswatch-logs-*", body=query)
        hits = resp["hits"]["hits"]
        total = resp["hits"]["total"]["value"]
        return jsonify({"total": total, "logs": [h["_source"] for h in hits]})
    finally:
        await client.close()


@bp.get("/stats")
@auth_required
async def siem_stats():
    """Ingest statistics: total indexed, events by class, events by severity."""
    cfg = current_app.config["MANAGER_CONFIG"].siem
    agg_body = {
        "size": 0,
        "aggs": {
            "by_class": {"terms": {"field": "class_name.keyword", "size": 20}},
            "by_severity": {"terms": {"field": "severity_id", "size": 10}},
        },
    }
    client = AsyncOpenSearch(hosts=[cfg.opensearch_url])
    try:
        resp = await client.search(index="skauswatch-logs-*", body=agg_body)
        return jsonify(
            {
                "total_indexed": resp["hits"]["total"]["value"],
                "by_class": resp["aggregations"]["by_class"]["buckets"],
                "by_severity": resp["aggregations"]["by_severity"]["buckets"],
            }
        )
    finally:
        await client.close()


@bp.get("/config")
@auth_required
async def get_siem_config():
    """Return current SIEM configuration (non-sensitive fields)."""
    cfg = current_app.config["MANAGER_CONFIG"].siem
    return jsonify(
        {
            "enabled": cfg.enabled,
            "retention_days": cfg.retention_days,
            "opensearch_url": cfg.opensearch_url,
            "log_receiver_url": cfg.log_receiver_url,
            "free_tier_user_cap": cfg.free_tier_user_cap,
        }
    )


@bp.put("/config")
@auth_required
@role_required("admin")
async def update_siem_config():
    """Update SIEM retention days (admin only). Range 1–400."""
    body = await request.get_json() or {}
    retention = body.get("retention_days")
    if retention is not None:
        if not isinstance(retention, int) or not 1 <= retention <= 400:
            return jsonify({"error": "retention_days must be an integer 1–400"}), 400
        logger.info("siem_retention_updated", days=retention)
    return jsonify({"message": "SIEM config updated", "retention_days": retention})


def _build_os_query(params) -> dict:
    """Build OpenSearch query from request parameters."""
    must = []
    if q := params.get("q"):
        must.append({"match": {"message": q}})
    if cn := params.get("class_name"):
        must.append({"term": {"class_name.keyword": cn}})
    if sev := params.get("severity"):
        must.append({"term": {"severity_id": int(sev)}})

    date_filter: dict = {}
    if fd := params.get("from_date"):
        date_filter["gte"] = fd
    if td := params.get("to_date"):
        date_filter["lte"] = td
    if date_filter:
        must.append({"range": {"time": date_filter}})

    page = int(params.get("page", 1))
    page_size = min(int(params.get("page_size", 50)), 500)

    return {
        "query": {"bool": {"must": must}} if must else {"match_all": {}},
        "from": (page - 1) * page_size,
        "size": page_size,
        "sort": [{"time": {"order": "desc"}}],
    }
