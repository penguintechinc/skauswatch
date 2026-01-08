"""Flask Backend Application Factory."""

from flask import Flask
from flask_cors import CORS
from prometheus_client import make_wsgi_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware

from .config import Config
from .models import init_db, get_db


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
        init_db(app)

    # Register blueprints
    from .auth import auth_bp
    from .users import users_bp
    from .hello import hello_bp

    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(users_bp, url_prefix="/api/v1/users")
    app.register_blueprint(hello_bp, url_prefix="/api/v1")

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
