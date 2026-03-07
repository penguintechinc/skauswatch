"""
SkausWatch PKI Server — Deprecation Shim (v1.x)

All PKI functionality has moved to icebox/services/pki-server/.
This shim forwards all requests to the IceBox PKI server and adds
deprecation headers to every response.

Shim behaviour:
  - Forwards GET/POST/PUT/PATCH/DELETE /api/v1/* → ICEBOX_PKI_URL
  - Adds Deprecation: true header
  - Adds Link: <{ICEBOX_PKI_URL}>; rel="successor-version" header
  - Logs all forwarded requests at WARNING level

This shim will be REMOVED in SkausWatch v2.0.0.
Migration guide: https://docs.penguintech.io/skauswatch/icebox/pki-migration
"""

from __future__ import annotations

import logging
import os
from datetime import datetime

import aiohttp
from quart import Quart, Response, jsonify, request
from quart_cors import cors

logger = logging.getLogger(__name__)

ICEBOX_PKI_URL = os.getenv("ICEBOX_PKI_URL", "http://icebox-pki:8081")
HOST = os.getenv("API_HOST", "0.0.0.0")
PORT = int(os.getenv("API_PORT", "8001"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING").upper()

logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.WARNING))

app = Quart(__name__)
app = cors(app, allow_origin="*")

_DEPRECATION_HEADERS = {
    "Deprecation": "true",
    "Link": f'<{ICEBOX_PKI_URL}>; rel="successor-version"',
    "Sunset": "SkausWatch v2.0.0",
}

# Hop-by-hop headers that must not be forwarded
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length",
})


@app.route("/healthz")
async def healthz():
    """Liveness probe — shim is always healthy if running."""
    return jsonify({
        "status": "healthy",
        "mode": "deprecation-shim",
        "successor": ICEBOX_PKI_URL,
        "timestamp": datetime.utcnow().isoformat(),
    })


@app.route("/api/v1/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_to_icebox(path: str):
    """Forward all PKI API requests to IceBox pki-server with deprecation headers."""
    target_url = f"{ICEBOX_PKI_URL}/api/v1/{path}"
    query_string = request.query_string.decode("utf-8")
    if query_string:
        target_url = f"{target_url}?{query_string}"

    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "host"
    }
    forward_headers["X-Forwarded-By"] = "skauswatch-pki-shim/v1"

    body = await request.get_data()

    logger.warning(
        "PKI shim: forwarding %s /api/v1/%s → %s (DEPRECATED: migrate to IceBox)",
        request.method,
        path,
        ICEBOX_PKI_URL,
    )

    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                data=body or None,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                content = await resp.read()
                response_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() not in _HOP_BY_HOP
                }
                response_headers.update(_DEPRECATION_HEADERS)

                return Response(
                    content,
                    status=resp.status,
                    headers=response_headers,
                    content_type=resp.content_type,
                )

    except aiohttp.ClientConnectorError as exc:
        logger.error("PKI shim: cannot reach IceBox PKI at %s: %s", ICEBOX_PKI_URL, exc)
        resp = jsonify({
            "error": "IceBox PKI service unavailable",
            "detail": f"Cannot connect to {ICEBOX_PKI_URL}. Ensure IceBox pki-server is deployed.",
            "migration": "https://docs.penguintech.io/skauswatch/icebox/pki-migration",
        })
        for k, v in _DEPRECATION_HEADERS.items():
            resp.headers[k] = v
        return resp, 503

    except Exception as exc:
        logger.error("PKI shim proxy error: %s", exc, exc_info=True)
        return jsonify({"error": "Proxy error", "detail": str(exc)}), 500


if __name__ == "__main__":
    import asyncio
    import hypercorn.asyncio
    from hypercorn.config import Config as HConfig

    hconfig = HConfig()
    hconfig.bind = [f"{HOST}:{PORT}"]
    hconfig.loglevel = "warning"

    logger.warning(
        "SkausWatch PKI Server running as DEPRECATION SHIM. "
        "Forwarding to IceBox PKI at %s. "
        "Migrate to IceBox before v2.0.0.",
        ICEBOX_PKI_URL,
    )
    asyncio.run(hypercorn.asyncio.serve(app, hconfig))
