"""Flask Backend Application Factory."""

from flask import Flask
from flask_cors import CORS
from prometheus_client import make_wsgi_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware

from .config import Config
from .models import init_db, get_db
from .db_schema import init_database_schema


def create_app(config_class: type = Config) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize CORS
    CORS(app, resources={
        r"/api/*": {
            "origins": app.config.get("CORS_ORIGINS", "*"),
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
        }
    })

    # Initialize database
    with app.app_context():
        # SQLAlchemy creates schema and handles migrations
        init_database_schema(app)
        # PyDAL for runtime operations only
        init_db(app)

    # Register blueprints - existing
    from .auth import auth_bp
    from .users import users_bp
    from .hello import hello_bp

    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(users_bp, url_prefix="/api/v1/users")
    app.register_blueprint(hello_bp, url_prefix="/api/v1")

    # Register blueprints - PR Reviewer API
    from .api.v1.reviews import reviews_bp
    from .api.v1.webhooks import webhooks_bp
    from .api.v1.repos import repos_bp
    from .api.v1.issues import issues_bp
    from .api.v1.credentials import credentials_bp
    from .api.v1.configs import configs_bp
    from .api.v1.providers import providers_bp
    from .api.v1.analytics import analytics_bp
    from .api.v1.licenses import licenses_bp
    from .api.v1.issue_plans import issue_plans_bp
    from .api.v1.platform_identities import platform_identities_bp

    app.register_blueprint(reviews_bp, url_prefix="/api/v1/reviews")
    app.register_blueprint(webhooks_bp, url_prefix="/api/v1/webhooks")
    app.register_blueprint(repos_bp, url_prefix="/api/v1/repos")
    app.register_blueprint(issues_bp, url_prefix="/api/v1/issues")
    app.register_blueprint(credentials_bp, url_prefix="/api/v1/credentials")
    app.register_blueprint(configs_bp, url_prefix="/api/v1/configs")
    app.register_blueprint(providers_bp, url_prefix="/api/v1/providers")
    app.register_blueprint(analytics_bp, url_prefix="/api/v1/analytics")
    app.register_blueprint(licenses_bp, url_prefix="/api/v1/licenses")
    app.register_blueprint(issue_plans_bp)
    app.register_blueprint(platform_identities_bp)

    # Health check endpoint
    @app.route("/healthz")
    def health_check():
        """Health check endpoint."""
        try:
            db = get_db()
            db.executesql("SELECT 1")
            return {"status": "healthy", "database": "connected"}, 200
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}, 503

    # Readiness check endpoint
    @app.route("/readyz")
    def readiness_check():
        """Readiness check endpoint."""
        return {"status": "ready"}, 200

    # Add Prometheus metrics endpoint
    app.wsgi_app = DispatcherMiddleware(
        app.wsgi_app,
        {"/metrics": make_wsgi_app()}
    )

    return app
