"""
Modules API endpoint.

Returns enabled sub-module flags to the WebUI and other consumers so they
can show/hide features without making additional round-trips.

GET /api/v1/modules — no authentication required.

Each sub-module is gated by a corresponding environment variable:
  CHECKPOINT_ENABLED      — Checkpoint identity provider sub-module
  ELDER_PUSH_ENABLED      — Elder identity push integration
  ICEBOX_ENABLED          — IceBox secrets vault sub-module
  DARWIN_ENABLED          — Darwin AI code-review sub-module
  ASM_ENABLED             — Attack-surface management sub-module
  SIEM_ENABLED            — SIEM integration sub-module
  S3_SCAN_ENABLED         — S3 bucket scanner sub-module
"""

from __future__ import annotations

import os

from quart import Blueprint, jsonify

bp = Blueprint("modules", __name__)


def _bool_env(key: str, default: str = "false") -> bool:
    """Return True when the env var resolves to 'true' (case-insensitive)."""
    return os.getenv(key, default).strip().lower() == "true"


@bp.route("", methods=["GET"])
async def get_modules() -> tuple:
    """
    Return enabled sub-module flags.

    No authentication required — this endpoint is intentionally public so
    the login page can adapt before the user is authenticated.

    Returns:
        JSON object where each key is a module name and the value is a bool.
    """
    modules: dict[str, bool] = {
        "checkpoint": _bool_env("CHECKPOINT_ENABLED", "false"),
        "elder_push": _bool_env("ELDER_PUSH_ENABLED", "false"),
        "icebox": _bool_env("ICEBOX_ENABLED", "false"),
        "darwin": _bool_env("DARWIN_ENABLED", "true"),
        "asm": _bool_env("ASM_ENABLED", "true"),
        "siem": _bool_env("SIEM_ENABLED", "true"),
        "s3_scan": _bool_env("S3_SCAN_ENABLED", "true"),
    }

    return (
        jsonify(
            {
                "modules": modules,
            }
        ),
        200,
    )
