"""PKI Server REST API v1."""

from quart import Blueprint

from .x509 import x509_bp
from .ssh import ssh_bp
from .common import common_bp

api_v1 = Blueprint("api_v1", __name__, url_prefix="/api/v1")

# Register sub-blueprints
api_v1.register_blueprint(x509_bp)
api_v1.register_blueprint(ssh_bp)
api_v1.register_blueprint(common_bp)

__all__ = ["api_v1"]
