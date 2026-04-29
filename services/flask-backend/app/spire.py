"""SPIRE API — REST facade over SPIRE Server gRPC admin API via kubectl exec."""

import asyncio
import json
import os
import re
import subprocess
from dataclasses import dataclass

import structlog
from quart import Blueprint, jsonify, request

from .middleware import auth_required

spire_bp = Blueprint("spire", __name__)
logger = structlog.get_logger(__name__)

SPIRE_ENABLED = os.getenv("SPIRE_ENABLED", "false").lower() == "true"
SPIRE_NAMESPACE = os.getenv("SPIRE_NAMESPACE", "skauswatch")
SPIRE_SERVER_LABEL = os.getenv(
    "SPIRE_SERVER_LABEL_SELECTOR",
    "component=server,app.kubernetes.io/name=skauswatch-spire",
)
SPIRE_SOCKET = "/tmp/spire-server/private/api.sock"

# Allowlists for user-supplied values passed to subprocess args.
_SPIFFE_ID_RE = re.compile(r"^spiffe://[a-zA-Z0-9._\-/]+$")
_TRUST_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9._\-]+$")
_ENTRY_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")
_SELECTOR_RE = re.compile(r"^[a-zA-Z0-9._\-/:]+$")


def _validate_spiffe_id(value: str) -> str:
    if not _SPIFFE_ID_RE.match(value):
        raise ValueError(f"Invalid SPIFFE ID: {value!r}")
    return value


def _validate_trust_domain(value: str) -> str:
    if not _TRUST_DOMAIN_RE.match(value):
        raise ValueError(f"Invalid trust domain: {value!r}")
    return value


def _validate_entry_id(value: str) -> str:
    if not _ENTRY_ID_RE.match(value):
        raise ValueError(f"Invalid entry ID: {value!r}")
    return value


def _validate_selector(value: str) -> str:
    if not _SELECTOR_RE.match(value):
        raise ValueError(f"Invalid selector: {value!r}")
    return value


@dataclass(slots=True)
class SpireStatus:
    healthy: bool
    uptime_seconds: int
    svid_count: int
    agent_count: int
    trust_domain: str


@dataclass(slots=True)
class SpireEntry:
    id: str
    spiffe_id: str
    parent_id: str
    selectors: list[str]
    ttl: int


@dataclass(slots=True)
class SpireEntryCreate:
    spiffe_id: str
    parent_id: str
    selectors: list[str]
    ttl: int = 3600


@dataclass(slots=True)
class SpireNode:
    id: str
    spiffe_id: str
    attestation_type: str
    banned: bool


@dataclass(slots=True)
class SpireJoinToken:
    token: str
    expires_at: str
    ttl: int


@dataclass(slots=True)
class SpireFederationPeer:
    trust_domain: str
    bundle_endpoint_url: str
    status: str


def _spire_unavailable():
    return jsonify({"error": "SPIRE not enabled or unavailable"}), 503


async def _get_spire_pod() -> str | None:
    """Resolve the running SPIRE server pod name."""
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            ["kubectl", "get", "pods", "-n", SPIRE_NAMESPACE,
             "-l", SPIRE_SERVER_LABEL, "-o", "jsonpath={.items[0].metadata.name}"],
            capture_output=True, text=True, timeout=10,
        )
        pod = result.stdout.strip()
        return pod if result.returncode == 0 and pod else None
    except Exception as exc:
        logger.error("spire_pod_lookup_failed", error=str(exc))
        return None


async def _exec(cmd: list[str], timeout: int = 30) -> str:
    """Run a spire-server subcommand via kubectl exec into the server pod.

    All cmd elements must be pre-validated before calling this function.
    subprocess.run is called with a list (never shell=True) to prevent injection.
    """
    pod = await _get_spire_pod()
    if not pod:
        raise RuntimeError("SPIRE server pod not found")

    full_cmd = (
        ["kubectl", "exec", "-n", SPIRE_NAMESPACE, pod, "--",
         "/opt/spire/bin/spire-server"]
        + cmd
        + ["-socketPath", SPIRE_SOCKET]
    )
    result = await asyncio.to_thread(
        subprocess.run, full_cmd, capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    return result.stdout


@spire_bp.route("/status", methods=["GET"])
@auth_required
async def get_spire_status() -> tuple:
    """Get SPIRE server health and summary stats."""
    if not SPIRE_ENABLED:
        return _spire_unavailable()
    try:
        out = await _exec(["healthcheck", "-output", "json"])
        data = json.loads(out) if out.strip() else {}
        return jsonify({
            "healthy": data.get("status") == "OK",
            "uptime_seconds": data.get("uptime_seconds", 0),
            "svid_count": data.get("svid_count", 0),
            "agent_count": data.get("agent_count", 0),
            "trust_domain": data.get("trust_domain", ""),
        }), 200
    except Exception as exc:
        logger.error("spire_status_failed", error=str(exc))
        return jsonify({"error": str(exc)}), 500


@spire_bp.route("/entries", methods=["GET"])
@auth_required
async def list_entries() -> tuple:
    """List all registered SPIFFE entries."""
    if not SPIRE_ENABLED:
        return _spire_unavailable()
    try:
        out = await _exec(["entry", "show", "-output", "json"])
        data = json.loads(out)
        entries = [
            {"id": e.get("id"), "spiffe_id": e.get("spiffe_id"),
             "parent_id": e.get("parent_id"), "selectors": e.get("selectors", []),
             "ttl": e.get("ttl", 0)}
            for e in data.get("entries", [])
        ]
        return jsonify({"entries": entries}), 200
    except Exception as exc:
        logger.error("spire_list_entries_failed", error=str(exc))
        return jsonify({"error": str(exc)}), 500


@spire_bp.route("/entries", methods=["POST"])
@auth_required
async def create_entry() -> tuple:
    """Register a new SPIFFE entry."""
    if not SPIRE_ENABLED:
        return _spire_unavailable()
    data = await request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    try:
        spiffe_id = _validate_spiffe_id(data.get("spiffe_id", ""))
        parent_id = _validate_spiffe_id(data.get("parent_id", ""))
        selectors = [_validate_selector(s) for s in data.get("selectors", [])]
        ttl: int = int(data.get("ttl", 3600))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    selector_args = [arg for s in selectors for arg in ("-selector", s)]
    try:
        out = await _exec(
            ["entry", "create", "-spiffeID", spiffe_id, "-parentID", parent_id]
            + selector_args + ["-ttl", str(ttl)]
        )
        entry_id = next(
            (line.split(":", 1)[1].strip() for line in out.splitlines() if "Entry ID:" in line),
            None,
        )
        return jsonify({"id": entry_id, "spiffe_id": spiffe_id, "parent_id": parent_id,
                        "selectors": selectors, "ttl": ttl}), 201
    except Exception as exc:
        logger.error("spire_create_entry_failed", error=str(exc))
        return jsonify({"error": str(exc)}), 500


@spire_bp.route("/entries/<entry_id>", methods=["DELETE"])
@auth_required
async def delete_entry(entry_id: str) -> tuple:
    """Delete a SPIFFE entry by ID."""
    if not SPIRE_ENABLED:
        return _spire_unavailable()
    try:
        entry_id = _validate_entry_id(entry_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        await _exec(["entry", "delete", "-entryID", entry_id])
        return "", 204
    except Exception as exc:
        logger.error("spire_delete_entry_failed", entry_id=entry_id, error=str(exc))
        return jsonify({"error": str(exc)}), 500


@spire_bp.route("/nodes", methods=["GET"])
@auth_required
async def list_nodes() -> tuple:
    """List attested SPIRE agents (nodes)."""
    if not SPIRE_ENABLED:
        return _spire_unavailable()
    try:
        out = await _exec(["agent", "list", "-output", "json"])
        data = json.loads(out)
        nodes = [
            {"id": a.get("id"), "spiffe_id": a.get("spiffe_id"),
             "attestation_type": a.get("attestation_type", "unknown"),
             "banned": a.get("banned", False)}
            for a in data.get("agents", [])
        ]
        return jsonify({"nodes": nodes}), 200
    except Exception as exc:
        logger.error("spire_list_nodes_failed", error=str(exc))
        return jsonify({"error": str(exc)}), 500


@spire_bp.route("/nodes/join-token", methods=["POST"])
@auth_required
async def create_join_token() -> tuple:
    """Generate a join token for enrolling a new LXD/VM node."""
    if not SPIRE_ENABLED:
        return _spire_unavailable()
    body = await request.get_json() or {}
    ttl: int = int(body.get("ttl", 3600))
    try:
        out = await _exec(["token", "generate", "-ttl", str(ttl), "-output", "json"])
        token_data = json.loads(out)
        return jsonify({"token": token_data.get("value"),
                        "expires_at": token_data.get("expires_at"),
                        "ttl": ttl}), 201
    except Exception as exc:
        logger.error("spire_join_token_failed", error=str(exc))
        return jsonify({"error": str(exc)}), 500


@spire_bp.route("/federation", methods=["GET"])
@auth_required
async def list_federation() -> tuple:
    """List federated trust domains."""
    if not SPIRE_ENABLED:
        return _spire_unavailable()
    try:
        out = await _exec(["federation", "list", "-output", "json"])
        data = json.loads(out)
        peers = [
            {"trust_domain": r.get("trust_domain"),
             "bundle_endpoint_url": r.get("bundle_endpoint_url"),
             "status": r.get("status", "unknown")}
            for r in data.get("relationships", [])
        ]
        return jsonify({"peers": peers}), 200
    except Exception as exc:
        logger.error("spire_list_federation_failed", error=str(exc))
        return jsonify({"error": str(exc)}), 500


@spire_bp.route("/federation/peers", methods=["POST"])
@auth_required
async def add_federation_peer() -> tuple:
    """Add a federation relationship with another trust domain."""
    if not SPIRE_ENABLED:
        return _spire_unavailable()
    data = await request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    try:
        trust_domain = _validate_trust_domain(data.get("trust_domain", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    bundle_endpoint_url: str = data.get("bundle_endpoint_url", "")
    if not bundle_endpoint_url.startswith("https://"):
        return jsonify({"error": "bundle_endpoint_url must be an HTTPS URL"}), 400

    try:
        await _exec(["federation", "create",
                     "-trustDomain", trust_domain,
                     "-bundleEndpointURL", bundle_endpoint_url])
        return jsonify({"trust_domain": trust_domain,
                        "bundle_endpoint_url": bundle_endpoint_url,
                        "status": "created"}), 201
    except Exception as exc:
        logger.error("spire_add_federation_failed", trust_domain=trust_domain, error=str(exc))
        return jsonify({"error": str(exc)}), 500


@spire_bp.route("/federation/peers/<trust_domain>", methods=["DELETE"])
@auth_required
async def delete_federation_peer(trust_domain: str) -> tuple:
    """Remove a federation relationship."""
    if not SPIRE_ENABLED:
        return _spire_unavailable()
    try:
        trust_domain = _validate_trust_domain(trust_domain)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    try:
        await _exec(["federation", "delete", "-trustDomain", trust_domain])
        return "", 204
    except Exception as exc:
        logger.error("spire_delete_federation_failed", trust_domain=trust_domain, error=str(exc))
        return jsonify({"error": str(exc)}), 500


@spire_bp.route("/datastore/migrate", methods=["POST"])
@auth_required
async def migrate_datastore() -> tuple:
    """Trigger datastore migration (e.g. SQLite → PostgreSQL). Returns 202 Accepted."""
    if not SPIRE_ENABLED:
        return _spire_unavailable()
    try:
        await _exec(["datastore", "migrate"], timeout=300)
        return jsonify({"message": "Datastore migration complete"}), 202
    except Exception as exc:
        logger.error("spire_migrate_failed", error=str(exc))
        return jsonify({"error": str(exc)}), 500
