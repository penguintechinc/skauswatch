"""
SkausWatch SSH CA — Deprecation Shim (v1.x)

All SSH CA functionality has moved to icebox/services/ssh-ca/.
This shim forwards all requests to the IceBox SSH CA and adds
deprecation headers to every response.

Shim behaviour:
  - Forwards all /api/v1/* requests → ICEBOX_SSH_CA_URL
  - Adds Deprecation: true header
  - Adds Link: successor-version header
  - Logs all forwards at WARNING level

This shim will be REMOVED in SkausWatch v2.0.0.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime

import aiohttp
from quart import Quart, Response, jsonify, request
from quart_cors import cors

logger = logging.getLogger(__name__)

ICEBOX_SSH_CA_URL = os.getenv("ICEBOX_SSH_CA_URL", "http://icebox-ssh-ca:8082")
HOST = os.getenv("API_HOST", "0.0.0.0")
PORT = int(os.getenv("API_PORT", "8002"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING").upper()

logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.WARNING))

app = Quart(__name__)
app = cors(app, allow_origin="*")

_DEPRECATION_HEADERS = {
    "Deprecation": "true",
    "Link": f'<{ICEBOX_SSH_CA_URL}>; rel="successor-version"',
    "Sunset": "SkausWatch v2.0.0",
}

_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length",
})


@app.route("/healthz")
async def healthz():
    """Liveness probe."""
    return jsonify({
        "status": "healthy",
        "mode": "deprecation-shim",
        "successor": ICEBOX_SSH_CA_URL,
        "timestamp": datetime.utcnow().isoformat(),
    })


@app.route("/api/v1/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_to_icebox(path: str):
    """Forward all SSH CA requests to IceBox ssh-ca with deprecation headers."""
    target_url = f"{ICEBOX_SSH_CA_URL}/api/v1/{path}"
    query_string = request.query_string.decode("utf-8")
    if query_string:
        target_url = f"{target_url}?{query_string}"

    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "host"
    }
    forward_headers["X-Forwarded-By"] = "skauswatch-ssh-ca-shim/v1"

    body = await request.get_data()

    logger.warning(
        "SSH CA shim: forwarding %s /api/v1/%s → %s (DEPRECATED)",
        request.method, path, ICEBOX_SSH_CA_URL,
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
        logger.error("SSH CA shim: cannot reach %s: %s", ICEBOX_SSH_CA_URL, exc)
        resp = jsonify({
            "error": "IceBox SSH CA service unavailable",
            "detail": f"Cannot connect to {ICEBOX_SSH_CA_URL}.",
        })
        for k, v in _DEPRECATION_HEADERS.items():
            resp.headers[k] = v
        return resp, 503

    except Exception as exc:
        logger.error("SSH CA shim error: %s", exc, exc_info=True)
        return jsonify({"error": "Proxy error", "detail": str(exc)}), 500


if __name__ == "__main__":
    import asyncio
    import hypercorn.asyncio
    from hypercorn.config import Config as HConfig

    hconfig = HConfig()
    hconfig.bind = [f"{HOST}:{PORT}"]
    hconfig.loglevel = "warning"
    logger.warning("SSH CA running as DEPRECATION SHIM → %s", ICEBOX_SSH_CA_URL)
    asyncio.run(hypercorn.asyncio.serve(app, hconfig))
