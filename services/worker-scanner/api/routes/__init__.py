"""API route blueprints for the worker-scanner service.

This module imports and exports all route blueprints for registration
with the Flask application. Each blueprint handles a specific API domain.

Blueprints:
    targets_bp: Scan target CRUD operations
    jobs_bp: Scan job management and execution
    findings_bp: Security finding retrieval, updates, and export
    schedules_bp: Scheduled scan management
    scanners_bp: Scanner status and health information
"""

from api.routes.targets import targets_bp
from api.routes.jobs import jobs_bp
from api.routes.findings import findings_bp
from api.routes.schedules import schedules_bp
from api.routes.scanners import scanners_bp

__all__ = [
    "targets_bp",
    "jobs_bp",
    "findings_bp",
    "schedules_bp",
    "scanners_bp",
    "register_blueprints",
]


def register_blueprints(app):
    """Register all API blueprints with the Flask application.

    Each blueprint is registered under the /api/v1/scanner URL prefix,
    following the project's API versioning standard.

    Args:
        app: The Flask application instance.
    """
    base = "/api/v1/scanner"
    app.register_blueprint(targets_bp, url_prefix=f"{base}/targets")
    app.register_blueprint(jobs_bp, url_prefix=f"{base}/jobs")
    app.register_blueprint(findings_bp, url_prefix=f"{base}/findings")
    app.register_blueprint(schedules_bp, url_prefix=f"{base}/schedules")
    app.register_blueprint(scanners_bp, url_prefix=base)
