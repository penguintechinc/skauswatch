"""API v1 Blueprints."""

from .reviews import reviews_bp
from .webhooks import webhooks_bp
from .repos import repos_bp
from .issues import issues_bp
from .credentials import credentials_bp
from .configs import configs_bp
from .providers import providers_bp
from .analytics import analytics_bp

__all__ = [
    "reviews_bp",
    "webhooks_bp",
    "repos_bp",
    "issues_bp",
    "credentials_bp",
    "configs_bp",
    "providers_bp",
    "analytics_bp",
]
