#!/usr/bin/env python3
"""Quart Backend Entry Point."""

import asyncio
import os
import sys
from typing import Optional

from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig

from app import create_app
from app.config import Config


async def wait_for_database(max_retries: int = 30, retry_delay: int = 2) -> bool:
    """Wait for database to be available."""
    from sqlalchemy import create_engine, text

    db_uri: str = Config.get_db_uri()
    print(f"Waiting for database: {Config.DB_HOST}:{Config.DB_PORT}")
    for attempt in range(1, max_retries + 1):
        try:
            engine = create_engine(db_uri, pool_size=1, pool_pre_ping=True)
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            engine.dispose()
            print(f"Database ready after {attempt} attempt(s)")
            return True
        except Exception as exc:
            print(f"DB attempt {attempt}/{max_retries} failed: {exc}")
            if attempt < max_retries:
                await asyncio.sleep(retry_delay)
    return False


async def create_default_admin(app) -> None:
    """Create default admin user if no users exist."""
    from sqlalchemy import create_engine, text

    from app.auth import hash_password
    from app.models import create_user, get_user_by_email

    async with app.app_context():
        # Check user count using SQLAlchemy sync to avoid async context issues at startup
        db_uri: str = Config.get_db_uri()
        engine = create_engine(db_uri)
        try:
            with engine.connect() as conn:
                result = conn.execute(text("SELECT COUNT(*) FROM users"))
                user_count = result.scalar()
        finally:
            engine.dispose()

        if user_count == 0:
            admin_email: str = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@example.com")
            admin_password: str = os.getenv(
                "DEFAULT_ADMIN_PASSWORD", "changeme123"
            )
            existing = await get_user_by_email(admin_email)
            if not existing:
                print(f"Creating default admin: {admin_email}")
                await create_user(
                    email=admin_email,
                    password_hash=hash_password(admin_password),
                    full_name="System Administrator",
                    role="admin",
                )
                print("WARNING: Change the default password immediately!")


async def main() -> None:
    """Main async entry point."""
    if not await wait_for_database():
        print("ERROR: Could not connect to database")
        sys.exit(1)

    app = create_app()
    await create_default_admin(app)

    host: str = os.getenv("APP_HOST", "0.0.0.0")
    port: int = int(os.getenv("APP_PORT", "8080"))

    config = HypercornConfig()
    config.bind = [f"{host}:{port}"]
    config.accesslog = "-"
    config.errorlog = "-"

    print(f"Starting Quart backend on {host}:{port}")
    await serve(app, config)


if __name__ == "__main__":
    asyncio.run(main())
