"""
SkausWatch Manager Service - Main Application

This module contains the main py4web application setup and configuration
for the SkausWatch Manager service.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

import structlog
from py4web import DAL, Session, Cache, Translator, Flash, action, redirect, URL
from py4web.core import Fixture
from py4web.utils.auth import Auth
from py4web.utils.publisher import Publisher
from pydal.tools.tags import Tags

from .models import get_database, close_database
from .config import ManagerConfig
from .auth import SkausWatchAuth
from .security import SecurityManager
from .health import HealthChecker
from .utils import setup_logging, get_version

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Application globals
config: Optional[ManagerConfig] = None
db: Optional[DAL] = None
auth: Optional[SkausWatchAuth] = None
security: Optional[SecurityManager] = None
health_checker: Optional[HealthChecker] = None

# py4web fixtures
session: Optional[Session] = None
cache: Optional[Cache] = None
translator: Optional[Translator] = None
flash: Optional[Flash] = None
tags: Optional[Tags] = None


class SkausWatchManagerApp:
    """Main SkausWatch Manager Application class"""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize the application
        
        Args:
            config_path: Path to configuration file
        """
        global config, db, auth, security, health_checker
        global session, cache, translator, flash, tags

        # Load configuration
        config = ManagerConfig(config_path)
        
        # Setup logging
        setup_logging(config.logging)
        
        logger.info(
            "Initializing SkausWatch Manager Service",
            version=get_version(),
            config_path=config_path
        )

        try:
            # Initialize database
            self._init_database()

            # Initialize py4web fixtures
            self._init_fixtures()

            # Initialize authentication
            self._init_auth()

            # Initialize security manager
            self._init_security()

            # Initialize health checker
            self._init_health_checker()

            # Register error handlers
            self._register_error_handlers()

            logger.info("SkausWatch Manager Service initialized successfully")

        except Exception as e:
            logger.error("Failed to initialize SkausWatch Manager Service", error=str(e))
            raise

    def _init_database(self) -> None:
        """Initialize database connection"""
        global db
        
        try:
            # Get database instance
            db_manager = get_database(
                db_uri=config.database.uri,
                migrate=config.database.migrate,
                fake_migrate=config.database.fake_migrate,
            )
            
            db = db_manager.db

            # Initialize default data if requested
            if config.database.init_default_data:
                db_manager.init_default_data()

            logger.info("Database initialized successfully")

        except Exception as e:
            logger.error("Failed to initialize database", error=str(e))
            raise

    def _init_fixtures(self) -> None:
        """Initialize py4web fixtures"""
        global session, cache, translator, flash, tags

        try:
            # Session management
            session = Session(
                secret=config.security.secret_key,
                expiration=config.auth.session_timeout,
                secure=config.security.secure_cookies,
                same_site="Lax"
            )

            # Caching
            cache = Cache(
                default_expiration=config.cache.default_expiration,
                redis=config.cache.redis_url if config.cache.redis_url else None
            )

            # Internationalization
            translator = Translator(
                path=Path(__file__).parent / "translations"
            )

            # Flash messages
            flash = Flash()

            # Tags for content tagging
            tags = Tags(db)

            logger.info("py4web fixtures initialized successfully")

        except Exception as e:
            logger.error("Failed to initialize py4web fixtures", error=str(e))
            raise

    def _init_auth(self) -> None:
        """Initialize authentication system"""
        global auth

        try:
            auth = SkausWatchAuth(
                db=db,
                config=config.auth,
                session=session
            )

            logger.info("Authentication system initialized successfully")

        except Exception as e:
            logger.error("Failed to initialize authentication", error=str(e))
            raise

    def _init_security(self) -> None:
        """Initialize security manager"""
        global security

        try:
            security = SecurityManager(
                db=db,
                config=config.security,
                auth=auth
            )

            logger.info("Security manager initialized successfully")

        except Exception as e:
            logger.error("Failed to initialize security manager", error=str(e))
            raise

    def _init_health_checker(self) -> None:
        """Initialize health checker"""
        global health_checker

        try:
            health_checker = HealthChecker(
                db=db,
                config=config.health_check
            )

            logger.info("Health checker initialized successfully")

        except Exception as e:
            logger.error("Failed to initialize health checker", error=str(e))
            raise

    def _register_error_handlers(self) -> None:
        """Register global error handlers"""
        # This will be implemented when we create the controllers
        pass

    def get_fixtures(self) -> Dict[str, Fixture]:
        """Get all fixtures for controllers"""
        return {
            "db": db,
            "auth": auth,
            "security": security,
            "session": session,
            "cache": cache,
            "translator": translator,
            "flash": flash,
            "tags": tags,
            "health_checker": health_checker,
        }

    def close(self) -> None:
        """Close application and cleanup resources"""
        try:
            # Close health checker
            if health_checker:
                health_checker.close()

            # Close database
            close_database()

            logger.info("SkausWatch Manager Service closed successfully")

        except Exception as e:
            logger.error("Error closing SkausWatch Manager Service", error=str(e))


# Global application instance
app: Optional[SkausWatchManagerApp] = None


def create_app(config_path: Optional[str] = None) -> SkausWatchManagerApp:
    """Create and configure the SkausWatch Manager application
    
    Args:
        config_path: Optional path to configuration file
        
    Returns:
        Configured application instance
    """
    global app
    
    if app is None:
        app = SkausWatchManagerApp(config_path)
    
    return app


def get_app() -> SkausWatchManagerApp:
    """Get the current application instance"""
    global app
    
    if app is None:
        raise RuntimeError("Application not initialized. Call create_app() first.")
    
    return app


@action("health", method="GET")
@action.uses()
def health_check():
    """Health check endpoint"""
    try:
        app = get_app()
        health_status = app.health_checker.check_all()
        
        # Return appropriate HTTP status
        status_code = 200 if health_status["status"] == "healthy" else 503
        
        return {
            "status": health_status["status"],
            "timestamp": health_status["timestamp"],
            "version": get_version(),
            "checks": health_status["checks"]
        }, status_code

    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return {
            "status": "error",
            "error": str(e),
            "version": get_version()
        }, 500


@action("version", method="GET")
@action.uses()
def version_info():
    """Version information endpoint"""
    return {
        "name": "SkausWatch Manager Service",
        "version": get_version(),
        "status": "running"
    }


@action("metrics", method="GET")
@action.uses(auth.user)
def metrics():
    """Prometheus metrics endpoint (requires authentication)"""
    try:
        # TODO: Implement metrics collection
        return "# Prometheus metrics not yet implemented", {"Content-Type": "text/plain"}

    except Exception as e:
        logger.error("Failed to generate metrics", error=str(e))
        return "# Error generating metrics", {"Content-Type": "text/plain"}


# Main entry point for development server
def main():
    """Main entry point for running the application"""
    import argparse
    import uvicorn
    from py4web import start_server

    parser = argparse.ArgumentParser(description="SkausWatch Manager Service")
    parser.add_argument(
        "--config", "-c",
        type=str,
        help="Configuration file path"
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host to bind to"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8000,
        help="Port to bind to"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development"
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Log level"
    )

    args = parser.parse_args()

    try:
        # Create application
        app = create_app(args.config)
        
        # Start py4web server
        start_server(
            host=args.host,
            port=args.port,
            reload=args.reload,
            logging_level=getattr(logging, args.log_level)
        )

    except KeyboardInterrupt:
        logger.info("Shutting down SkausWatch Manager Service...")
    except Exception as e:
        logger.error("Failed to start SkausWatch Manager Service", error=str(e))
        sys.exit(1)
    finally:
        if app:
            app.close()


if __name__ == "__main__":
    main()