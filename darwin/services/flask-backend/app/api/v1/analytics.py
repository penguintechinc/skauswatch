"""Usage Statistics API Endpoints."""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta

from ...middleware import auth_required
from ...models import (
    get_db,
    list_reviews,
    get_usage_stats,
)

analytics_bp = Blueprint("analytics", __name__, url_prefix="/api/v1/analytics")


@analytics_bp.route("/reviews/summary", methods=["GET"])
@auth_required
def get_reviews_summary():
    """Get summary statistics for all reviews."""
    # Get all reviews
    reviews, total = list_reviews(page=1, per_page=10000)

    # Calculate statistics
    by_status = {}
    by_platform = {}
    total_files = 0
    total_comments = 0

    for review in reviews:
        # Count by status
        status = review.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1

        # Count by platform
        platform = review.get("platform", "unknown")
        by_platform[platform] = by_platform.get(platform, 0) + 1

        # Aggregate metrics
        total_files += review.get("files_reviewed", 0)
        total_comments += review.get("comments_posted", 0)

    # Calculate success rate
    completed = by_status.get("completed", 0)
    success_rate = (completed / total * 100) if total > 0 else 0

    return jsonify({
        "total_reviews": total,
        "by_status": by_status,
        "by_platform": by_platform,
        "total_files_reviewed": total_files,
        "total_comments_posted": total_comments,
        "success_rate": round(success_rate, 2),
        "average_files_per_review": round(total_files / total, 2) if total > 0 else 0,
        "average_comments_per_review": round(total_comments / total, 2) if total > 0 else 0,
    }), 200


@analytics_bp.route("/reviews/timeline", methods=["GET"])
@auth_required
def get_reviews_timeline():
    """Get review statistics over time."""
    days = request.args.get("days", 30, type=int)
    bin_size = request.args.get("bin_size", "day")  # day, week, month

    db = get_db()

    # Get date range
    start_date = datetime.utcnow() - timedelta(days=days)

    # Get reviews in time range
    reviews = db(db.reviews.created_at >= start_date).select()

    # Bin reviews by time
    timeline = {}

    for review in reviews:
        created = review.created_at
        if bin_size == "hour":
            key = created.strftime("%Y-%m-%d %H:00")
        elif bin_size == "week":
            key = created.strftime("%Y-W%W")
        else:  # day
            key = created.strftime("%Y-%m-%d")

        if key not in timeline:
            timeline[key] = {"total": 0, "completed": 0, "failed": 0}

        timeline[key]["total"] += 1
        if review.status == "completed":
            timeline[key]["completed"] += 1
        elif review.status == "failed":
            timeline[key]["failed"] += 1

    # Sort by date
    sorted_timeline = sorted(timeline.items())

    return jsonify({
        "period_days": days,
        "bin_size": bin_size,
        "data": [{"date": k, **v} for k, v in sorted_timeline],
    }), 200


@analytics_bp.route("/usage/by-provider", methods=["GET"])
@auth_required
def get_usage_by_provider():
    """Get token usage breakdown by AI provider."""
    days = request.args.get("days", 30, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)

    db = get_db()

    # Get all unique providers
    providers = set()
    usage_records = db(db.provider_usage.created_at >= start_date).select()

    for record in usage_records:
        if record.provider:
            providers.add(record.provider)

    # Get stats for each provider
    provider_stats = []

    for provider in sorted(providers):
        stats = get_usage_stats(provider=provider, start_date=start_date)
        provider_stats.append({
            "provider": provider,
            "total_tokens": stats.get("total_tokens", 0),
            "total_cost": round(stats.get("total_cost", 0), 4),
            "total_requests": stats.get("total_requests", 0),
        })

    # Sort by tokens
    provider_stats.sort(key=lambda x: x["total_tokens"], reverse=True)

    total_tokens = sum(p["total_tokens"] for p in provider_stats)
    total_cost = sum(p["total_cost"] for p in provider_stats)

    return jsonify({
        "period_days": days,
        "total_tokens": total_tokens,
        "total_cost": round(total_cost, 4),
        "providers": provider_stats,
    }), 200


@analytics_bp.route("/usage/by-model", methods=["GET"])
@auth_required
def get_usage_by_model():
    """Get token usage breakdown by AI model."""
    days = request.args.get("days", 30, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)

    db = get_db()

    # Get all models
    models_data = db(db.provider_usage.created_at >= start_date).select()
    models = set(u.model for u in models_data if u.model)

    # Get stats for each model
    model_stats = []

    for model in sorted(models):
        model_usage = db(
            (db.provider_usage.model == model) &
            (db.provider_usage.created_at >= start_date)
        ).select()

        total_tokens = sum(u.total_tokens for u in model_usage)
        total_cost = sum(u.cost_estimate for u in model_usage)
        total_requests = len(model_usage)

        model_stats.append({
            "model": model,
            "total_tokens": total_tokens,
            "total_cost": round(total_cost, 4),
            "total_requests": total_requests,
        })

    # Sort by tokens
    model_stats.sort(key=lambda x: x["total_tokens"], reverse=True)

    total_tokens = sum(m["total_tokens"] for m in model_stats)
    total_cost = sum(m["total_cost"] for m in model_stats)

    return jsonify({
        "period_days": days,
        "total_tokens": total_tokens,
        "total_cost": round(total_cost, 4),
        "models": model_stats,
    }), 200


@analytics_bp.route("/latency/summary", methods=["GET"])
@auth_required
def get_latency_summary():
    """Get latency statistics for API calls."""
    days = request.args.get("days", 7, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)

    db = get_db()

    # Get all usage records
    usage_records = db(db.provider_usage.created_at >= start_date).select()

    if not usage_records:
        return jsonify({
            "period_days": days,
            "total_requests": 0,
        }), 200

    latencies = [u.latency_ms for u in usage_records if u.latency_ms]

    if not latencies:
        return jsonify({
            "period_days": days,
            "total_requests": len(usage_records),
            "avg_latency_ms": None,
        }), 200

    latencies.sort()
    total = len(latencies)

    return jsonify({
        "period_days": days,
        "total_requests": len(usage_records),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 2),
        "min_latency_ms": min(latencies),
        "max_latency_ms": max(latencies),
        "median_latency_ms": latencies[total // 2],
        "p95_latency_ms": latencies[int(total * 0.95)] if total > 20 else None,
        "p99_latency_ms": latencies[int(total * 0.99)] if total > 100 else None,
    }), 200


@analytics_bp.route("/latency/by-provider", methods=["GET"])
@auth_required
def get_latency_by_provider():
    """Get latency breakdown by AI provider."""
    days = request.args.get("days", 7, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)

    db = get_db()

    # Get all unique providers
    providers = set()
    usage_records = db(db.provider_usage.created_at >= start_date).select()

    for record in usage_records:
        if record.provider:
            providers.add(record.provider)

    # Get latency stats for each provider
    provider_latencies = []

    for provider in sorted(providers):
        provider_records = db(
            (db.provider_usage.provider == provider) &
            (db.provider_usage.created_at >= start_date)
        ).select()

        latencies = [u.latency_ms for u in provider_records if u.latency_ms]

        if latencies:
            latencies.sort()
            avg = round(sum(latencies) / len(latencies), 2)
            provider_latencies.append({
                "provider": provider,
                "avg_latency_ms": avg,
                "min_latency_ms": min(latencies),
                "max_latency_ms": max(latencies),
                "requests": len(provider_records),
            })

    # Sort by avg latency
    provider_latencies.sort(key=lambda x: x["avg_latency_ms"])

    return jsonify({
        "period_days": days,
        "providers": provider_latencies,
    }), 200


@analytics_bp.route("/issues/summary", methods=["GET"])
@auth_required
def get_issues_summary():
    """Get summary statistics for all issues/comments."""
    db = get_db()

    # Count by severity
    severities = ["critical", "major", "minor", "suggestion"]
    by_severity = {}

    for sev in severities:
        count = db(db.review_comments.severity == sev).count()
        by_severity[sev] = count

    # Count by category
    categories = ["security", "best_practices", "framework", "iac"]
    by_category = {}

    for cat in categories:
        count = db(db.review_comments.category == cat).count()
        by_category[cat] = count

    # Count by status
    statuses = ["open", "acknowledged", "fixed", "wont_fix", "false_positive"]
    by_status = {}

    for stat in statuses:
        count = db(db.review_comments.status == stat).count()
        by_status[stat] = count

    total = db(db.review_comments.id > 0).count()

    return jsonify({
        "total_issues": total,
        "by_severity": by_severity,
        "by_category": by_category,
        "by_status": by_status,
    }), 200


@analytics_bp.route("/repositories/activity", methods=["GET"])
@auth_required
def get_repositories_activity():
    """Get activity statistics for repositories."""
    db = get_db()

    # Get all reviews grouped by repository
    reviews, _ = list_reviews(page=1, per_page=10000)

    repo_stats = {}

    for review in reviews:
        key = f"{review.get('platform')}/{review.get('repository')}"
        if key not in repo_stats:
            repo_stats[key] = {
                "platform": review.get("platform"),
                "repository": review.get("repository"),
                "total_reviews": 0,
                "completed": 0,
                "failed": 0,
                "total_files": 0,
                "total_comments": 0,
            }

        repo_stats[key]["total_reviews"] += 1
        if review.get("status") == "completed":
            repo_stats[key]["completed"] += 1
        elif review.get("status") == "failed":
            repo_stats[key]["failed"] += 1
        repo_stats[key]["total_files"] += review.get("files_reviewed", 0)
        repo_stats[key]["total_comments"] += review.get("comments_posted", 0)

    # Sort by review count
    sorted_repos = sorted(repo_stats.values(), key=lambda x: x["total_reviews"], reverse=True)

    return jsonify({
        "total_repositories": len(sorted_repos),
        "repositories": sorted_repos,
    }), 200


@analytics_bp.route("/export/csv", methods=["GET"])
@auth_required
def export_analytics_csv():
    """Export analytics data as CSV."""
    report_type = request.args.get("type", "reviews")  # reviews, issues, usage

    db = get_db()
    csv_data = []

    if report_type == "reviews":
        reviews, _ = list_reviews(page=1, per_page=10000)
        csv_data = ["id,external_id,platform,repository,status,files_reviewed,comments_posted,created_at"]
        for review in reviews:
            csv_data.append(
                f"{review.get('id')},{review.get('external_id')},"
                f"{review.get('platform')},{review.get('repository')},"
                f"{review.get('status')},{review.get('files_reviewed')},"
                f"{review.get('comments_posted')},{review.get('created_at')}"
            )

    elif report_type == "issues":
        issues = db(db.review_comments.id > 0).select()
        csv_data = ["id,review_id,file_path,category,severity,status,created_at"]
        for issue in issues:
            csv_data.append(
                f"{issue.id},{issue.review_id},{issue.file_path},"
                f"{issue.category},{issue.severity},{issue.status},{issue.created_at}"
            )

    elif report_type == "usage":
        usage = db(db.provider_usage.id > 0).select()
        csv_data = ["id,review_id,provider,model,total_tokens,cost_estimate,created_at"]
        for u in usage:
            csv_data.append(
                f"{u.id},{u.review_id},{u.provider},{u.model},"
                f"{u.total_tokens},{u.cost_estimate},{u.created_at}"
            )

    return "\n".join(csv_data), 200, {"Content-Type": "text/csv"}
