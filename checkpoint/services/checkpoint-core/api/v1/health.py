"""
checkpoint-core — health check endpoint.

GET /health → {"status": "ok", "service": "checkpoint-core", "version": "..."}
"""
from __future__ import annotations

import os

from quart import Blueprint, jsonify

health_bp = Blueprint("health", __name__)

_VERSION = os.environ.get("CHECKPOINT_VERSION", "0.0.0")


@health_bp.route("/health", methods=["GET"])
async def health():
    """Liveness health check — returns 200 when the service is running."""
    return jsonify(
        {
            "status": "ok",
            "service": "checkpoint-core",
            "version": _VERSION,
        }
    )
