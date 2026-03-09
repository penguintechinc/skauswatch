"""IceBox REST API v1 blueprints."""

from quart import Blueprint

from .admin import bp as admin_bp
from .audit import bp as audit_bp
from .jit import bp as jit_bp
from .one_time import bp as one_time_bp
from .secrets import bp as secrets_bp
from .sync import bp as sync_bp

api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")

api_v1.register_blueprint(secrets_bp, url_prefix="/secrets")
api_v1.register_blueprint(jit_bp, url_prefix="/jit")
api_v1.register_blueprint(one_time_bp, url_prefix="/one-time-secrets")
api_v1.register_blueprint(sync_bp, url_prefix="/sync")
api_v1.register_blueprint(admin_bp, url_prefix="/admin")
api_v1.register_blueprint(audit_bp, url_prefix="/audit")

__all__ = ["api_v1"]
