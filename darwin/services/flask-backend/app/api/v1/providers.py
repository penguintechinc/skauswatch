"""AI Provider Status API Endpoints."""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta

from ...middleware import auth_required
from ...models import (
    get_db,
    get_usage_stats,
)

providers_bp = Blueprint("providers", __name__, url_prefix="/api/v1/providers")


@providers_bp.route("", methods=["GET"])
@auth_required
def list_provider_status():
    """Get status of all AI providers."""
    db = get_db()

    # Get unique providers from usage data
    usage_records = db(db.provider_usage.id > 0).select()
    providers = list(set(r.provider for r in usage_records if r.provider))

    # Get default providers
    default_providers = ["claude", "gpt-4", "gpt-3.5-turbo"]
    all_providers = list(set(default_providers + providers))

    provider_status = []

    for provider in all_providers:
        # Get recent usage (last 24 hours)
        start_date = datetime.utcnow() - timedelta(hours=24)
        recent_usage = get_usage_stats(provider=provider, start_date=start_date)

        # Determine status based on recent activity
        status = "active" if recent_usage.get("total_requests", 0) > 0 else "inactive"

        provider_status.append({
            "name": provider,
            "status": status,
            "total_requests": recent_usage.get("total_requests", 0),
            "total_tokens": recent_usage.get("total_tokens", 0),
            "estimated_cost": round(recent_usage.get("total_cost", 0), 4),
        })

    # Sort by total requests
    provider_status.sort(key=lambda x: x["total_requests"], reverse=True)

    return jsonify({
        "data": provider_status,
        "total_providers": len(provider_status),
    }), 200


@providers_bp.route("/<provider_name>", methods=["GET"])
@auth_required
def get_provider_status(provider_name: str):
    """Get detailed status for a specific provider."""
    db = get_db()

    # Get all usage data for this provider
    usage = db(db.provider_usage.provider == provider_name).select()

    if not usage:
        return jsonify({
            "provider": provider_name,
            "status": "inactive",
            "total_requests": 0,
            "total_tokens": 0,
            "estimated_cost": 0,
        }), 200

    total_requests = len(usage)
    total_tokens = sum(u.total_tokens for u in usage)
    total_cost = sum(u.cost_estimate for u in usage)

    # Get recent usage (last 7 days)
    start_date = datetime.utcnow() - timedelta(days=7)
    recent_usage = get_usage_stats(provider=provider_name, start_date=start_date)

    # Get models used with this provider
    models = list(set(u.model for u in usage if u.model))

    # Calculate average latency
    latencies = [u.latency_ms for u in usage if u.latency_ms]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0

    return jsonify({
        "provider": provider_name,
        "status": "active",
        "total_requests": total_requests,
        "total_tokens": total_tokens,
        "estimated_cost": round(total_cost, 4),
        "average_latency_ms": avg_latency,
        "models": models,
        "recent_usage_7d": {
            "requests": recent_usage.get("total_requests", 0),
            "tokens": recent_usage.get("total_tokens", 0),
            "cost": round(recent_usage.get("total_cost", 0), 4),
        },
    }), 200


@providers_bp.route("/<provider_name>/models", methods=["GET"])
@auth_required
def get_provider_models(provider_name: str):
    """Get models available for a specific provider."""
    db = get_db()

    # Get all models used with this provider
    models_data = db(db.provider_usage.provider == provider_name).select(
        db.provider_usage.model,
        db.provider_usage.id.count(),
    )

    models = []
    for row in models_data:
        model_name = row.provider_usage.model
        request_count = row[db.provider_usage.id.count()]

        model_detail = db(
            (db.provider_usage.provider == provider_name) &
            (db.provider_usage.model == model_name)
        ).select().first()

        if model_detail:
            models.append({
                "name": model_name,
                "requests": request_count,
                "total_tokens": sum(u.total_tokens for u in db(
                    (db.provider_usage.provider == provider_name) &
                    (db.provider_usage.model == model_name)
                ).select()),
            })

    return jsonify({
        "provider": provider_name,
        "models": models,
        "total_models": len(models),
    }), 200


@providers_bp.route("/health", methods=["GET"])
@auth_required
def check_all_providers_health():
    """Check health status of all providers."""
    # This endpoint checks if providers are responsive
    # In a real implementation, this would ping the actual provider APIs

    providers_health = []

    default_providers = [
        {"name": "claude", "url": "https://api.anthropic.com"},
        {"name": "gpt-4", "url": "https://api.openai.com"},
        {"name": "gpt-3.5-turbo", "url": "https://api.openai.com"},
    ]

    for provider_info in default_providers:
        # Simple status - in production would actually check connectivity
        providers_health.append({
            "provider": provider_info["name"],
            "status": "unknown",
            "last_checked": datetime.utcnow().isoformat(),
            "note": "Actual health check requires valid API credentials",
        })

    return jsonify({
        "data": providers_health,
        "timestamp": datetime.utcnow().isoformat(),
    }), 200


@providers_bp.route("/<provider_name>/health", methods=["GET"])
@auth_required
def check_provider_health(provider_name: str):
    """Check health status of a specific provider."""
    # In a real implementation, this would ping the actual provider API
    # For now, return status based on recent usage

    db = get_db()

    # Check if provider has been used recently (last 7 days)
    start_date = datetime.utcnow() - timedelta(days=7)
    recent_usage = db(
        (db.provider_usage.provider == provider_name) &
        (db.provider_usage.created_at >= start_date)
    ).select()

    recent_requests = len(recent_usage)
    avg_latency = None

    if recent_usage:
        latencies = [u.latency_ms for u in recent_usage if u.latency_ms]
        if latencies:
            avg_latency = round(sum(latencies) / len(latencies), 2)

    return jsonify({
        "provider": provider_name,
        "status": "available" if recent_requests > 0 else "inactive",
        "recent_requests_7d": recent_requests,
        "average_latency_ms": avg_latency,
        "last_checked": datetime.utcnow().isoformat(),
    }), 200


@providers_bp.route("/costs/summary", methods=["GET"])
@auth_required
def get_costs_summary():
    """Get cost summary across all providers."""
    db = get_db()

    # Get date range
    days = request.args.get("days", 30, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)

    # Get all usage data for the period
    usage_records = db(
        db.provider_usage.created_at >= start_date
    ).select()

    # Aggregate by provider
    costs_by_provider = {}
    tokens_by_provider = {}
    requests_by_provider = {}

    for record in usage_records:
        provider = record.provider
        if provider not in costs_by_provider:
            costs_by_provider[provider] = 0
            tokens_by_provider[provider] = 0
            requests_by_provider[provider] = 0

        costs_by_provider[provider] += record.cost_estimate
        tokens_by_provider[provider] += record.total_tokens
        requests_by_provider[provider] += 1

    # Build response
    provider_costs = []
    total_cost = 0

    for provider in costs_by_provider:
        cost = round(costs_by_provider[provider], 4)
        total_cost += cost
        provider_costs.append({
            "provider": provider,
            "total_cost": cost,
            "total_tokens": tokens_by_provider[provider],
            "total_requests": requests_by_provider[provider],
        })

    # Sort by cost
    provider_costs.sort(key=lambda x: x["total_cost"], reverse=True)

    return jsonify({
        "period_days": days,
        "start_date": start_date.isoformat(),
        "end_date": datetime.utcnow().isoformat(),
        "total_cost": round(total_cost, 4),
        "providers": provider_costs,
    }), 200


@providers_bp.route("/<provider_name>/costs", methods=["GET"])
@auth_required
def get_provider_costs(provider_name: str):
    """Get cost breakdown for a specific provider."""
    db = get_db()

    # Get date range
    days = request.args.get("days", 30, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)

    # Get usage data for this provider
    usage_records = db(
        (db.provider_usage.provider == provider_name) &
        (db.provider_usage.created_at >= start_date)
    ).select()

    if not usage_records:
        return jsonify({
            "provider": provider_name,
            "period_days": days,
            "total_cost": 0,
            "total_tokens": 0,
            "total_requests": 0,
        }), 200

    total_cost = sum(u.cost_estimate for u in usage_records)
    total_tokens = sum(u.total_tokens for u in usage_records)
    total_requests = len(usage_records)

    # Cost breakdown by model
    costs_by_model = {}
    for record in usage_records:
        model = record.model or "unknown"
        if model not in costs_by_model:
            costs_by_model[model] = 0
        costs_by_model[model] += record.cost_estimate

    return jsonify({
        "provider": provider_name,
        "period_days": days,
        "start_date": start_date.isoformat(),
        "total_cost": round(total_cost, 4),
        "total_tokens": total_tokens,
        "total_requests": total_requests,
        "costs_by_model": {k: round(v, 4) for k, v in costs_by_model.items()},
    }), 200
