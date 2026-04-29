"""Quart Backend Application Factory."""

from pathlib import Path
from typing import Tuple

from quart import Quart, jsonify
from quart_cors import cors

from .config import Config
from .middleware import LocalTokenValidator


def create_app(config_class: type = Config) -> Quart:
    """Create and configure the Quart application."""
    app = Quart(__name__)
    app.config.from_object(config_class)

    # Initialize CORS
    app = cors(
        app,
        allow_origin=app.config.get("CORS_ORIGINS", "*"),
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

    @app.before_serving
    async def startup() -> None:
        """Initialize database and OIDC provider."""
        from penguin_aaa import FileKeyStore, MemoryKeyStore, MemoryTokenStore, OIDCProvider
        from penguin_aaa.authn.oidc_provider import OIDCProviderConfig
        from penguin_dal.quart_ext import init_dal

        # Database
        init_dal(app, uri=config_class.get_db_uri(), pool_size=config_class.DB_POOL_SIZE)

        # Key store — file-backed in production, memory for testing/dev
        key_dir = Path(app.config.get("JWT_KEY_DIR", "/tmp/skauswatch-keys"))
        key_file = key_dir / "jwks.json"
        try:
            key_dir.mkdir(parents=True, exist_ok=True)
            keystore = FileKeyStore(path=key_file, algorithm="RS256")
        except Exception:
            keystore = MemoryKeyStore(algorithm="RS256")

        # OIDC Provider
        issuer = app.config.get("ISSUER_URL", "http://localhost:8080")
        audience = app.config.get("JWT_AUDIENCE", "skauswatch")
        provider_config = OIDCProviderConfig(
            issuer=issuer,
            audiences=[audience],
            algorithm="RS256",
        )
        token_store = MemoryTokenStore()
        provider = OIDCProvider(config=provider_config, keystore=keystore, token_store=token_store)
        app.extensions["oidc_provider"] = provider
        app.extensions["token_validator"] = LocalTokenValidator(
            provider=provider,
            issuer=issuer,
            audiences=[audience],
        )

    # Register blueprints
    from .auth import auth_bp
    from .hello import hello_bp
    from .spire import spire_bp
    from .users import users_bp

    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(users_bp, url_prefix="/api/v1/users")
    app.register_blueprint(spire_bp, url_prefix="/api/v1/spire")
    app.register_blueprint(hello_bp, url_prefix="/api/v1")

    # OIDC discovery endpoints
    @app.route("/.well-known/openid-configuration")
    async def oidc_discovery() -> Tuple[dict, int]:
        provider = app.extensions.get("oidc_provider")
        if not provider:
            return jsonify({"error": "OIDC provider not initialized"}), 503
        return jsonify(provider.discovery_document()), 200

    @app.route("/.well-known/jwks.json")
    async def jwks() -> Tuple[dict, int]:
        provider = app.extensions.get("oidc_provider")
        if not provider:
            return jsonify({"error": "OIDC provider not initialized"}), 503
        return jsonify(provider.jwks()), 200

    # OpenAPI spec endpoint
    @app.route("/api/v1/openapi.json")
    async def openapi_spec() -> Tuple[dict, int]:
        import yaml
        from pathlib import Path as _Path
        spec_path = _Path(__file__).parent.parent / "openapi" / "v1.yaml"
        if not spec_path.exists():
            return jsonify({"error": "OpenAPI spec not found"}), 404
        with open(spec_path) as f:
            spec = yaml.safe_load(f)
        return jsonify(spec), 200

    # Health check endpoint
    @app.route("/healthz")
    async def health_check() -> Tuple[dict, int]:
        from penguin_dal.quart_ext import get_db
        try:
            db = get_db()
            # Simple connectivity check
            await db(db.users.id >= 0).count()
            return jsonify({"status": "healthy", "database": "connected"}), 200
        except Exception as e:
            return jsonify({"status": "unhealthy", "error": str(e)}), 503

    # Readiness check endpoint
    @app.route("/readyz")
    async def readiness_check() -> Tuple[dict, int]:
        return jsonify({"status": "ready"}), 200

    # Prometheus metrics endpoint
    @app.route("/metrics")
    async def metrics_endpoint() -> Tuple[str, int, dict]:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
        return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

    return app
