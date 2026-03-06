#!/usr/bin/env python3
"""Standalone script to initialize admin user in the default tenant.

This script creates an admin user with:
- email: admin@localhost.local
- password: admin123 (bcrypt hashed)
- role: admin
- global_role: admin
- default_tenant_id: 1 (default tenant)

Adds admin to default tenant (id=1) as admin role
Adds admin to default team (id=1) as admin role

Only creates if admin doesn't already exist (checked by email)
"""

import os
import sys
import time
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pydal import DAL, Field
from app.config import Config
import bcrypt


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def wait_for_database(max_retries: int = 30, retry_delay: int = 2) -> bool:
    """Wait for database to be available."""
    db_uri = Config.get_db_uri()
    print(f"[*] Waiting for database connection: {Config.DB_HOST}:{Config.DB_PORT}")

    for attempt in range(1, max_retries + 1):
        try:
            db = DAL(db_uri, pool_size=1, migrate=False)
            db.executesql("SELECT 1")
            db.close()
            print(f"[+] Database connection successful after {attempt} attempt(s)")
            return True
        except Exception as e:
            if attempt < max_retries:
                print(f"[-] Database connection attempt {attempt}/{max_retries} failed: {e}")
                time.sleep(retry_delay)
            else:
                print(f"[-] Database connection failed after {max_retries} attempts: {e}")

    return False


def init_db() -> DAL:
    """Initialize database connection and tables using PyDAL."""
    db_uri = Config.get_db_uri()

    migration_folder = os.environ.get("PYDAL_MIGRATION_FOLDER", "/tmp/pydal_migrations")
    os.makedirs(migration_folder, exist_ok=True)

    db = DAL(
        db_uri,
        pool_size=Config.DB_POOL_SIZE,
        migrate=True,
        fake_migrate_all=True,
        check_reserved=["all"],
        lazy_tables=False,
        folder=migration_folder,
    )

    # Define tenants table
    db.define_table(
        "tenants",
        Field("name", "string", length=255, unique=True),
        Field("slug", "string", length=128, unique=True),
        Field("description", "text"),
        Field("is_active", "boolean", default=True),
        Field("max_users", "integer", default=0),
        Field("max_repositories", "integer", default=0),
        Field("max_teams", "integer", default=0),
        Field("settings", "json", default={}),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
        format="%(name)s",
    )

    # Define users table
    db.define_table(
        "users",
        Field("email", "string", length=255, unique=True),
        Field("password_hash", "string", length=255),
        Field("full_name", "string", length=255),
        Field("role", "string", length=50, default="viewer"),
        Field("global_role", "string", length=50, default="viewer"),
        Field("default_tenant_id", "reference tenants", ondelete="SET NULL"),
        Field("is_active", "boolean", default=True),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Define teams table
    db.define_table(
        "teams",
        Field("tenant_id", "reference tenants", ondelete="CASCADE"),
        Field("name", "string", length=255),
        Field("slug", "string", length=128),
        Field("description", "text"),
        Field("is_active", "boolean", default=True),
        Field("is_default", "boolean", default=False),
        Field("settings", "json", default={}),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
        format="%(name)s",
    )

    # Define tenant_members table
    db.define_table(
        "tenant_members",
        Field("tenant_id", "reference tenants", ondelete="CASCADE"),
        Field("user_id", "reference users", ondelete="CASCADE"),
        Field("role", "string", length=50, default="viewer"),
        Field("custom_role_id", "reference custom_roles", ondelete="SET NULL"),
        Field("scopes", "json", default=[]),
        Field("is_active", "boolean", default=True),
        Field("joined_at", "datetime", default=datetime.utcnow),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Define team_members table
    db.define_table(
        "team_members",
        Field("team_id", "reference teams", ondelete="CASCADE"),
        Field("user_id", "reference users", ondelete="CASCADE"),
        Field("role", "string", length=50, default="viewer"),
        Field("custom_role_id", "reference custom_roles", ondelete="SET NULL"),
        Field("scopes", "json", default=[]),
        Field("is_active", "boolean", default=True),
        Field("joined_at", "datetime", default=datetime.utcnow),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Define custom_roles table (needed for foreign keys)
    db.define_table(
        "custom_roles",
        Field("tenant_id", "reference tenants", ondelete="CASCADE"),
        Field("team_id", "reference teams", ondelete="CASCADE"),
        Field("name", "string", length=128),
        Field("slug", "string", length=128),
        Field("description", "text"),
        Field("role_level", "string"),
        Field("scopes", "json"),
        Field("is_active", "boolean", default=True),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
        format="%(name)s",
    )

    db.commit()
    return db


def create_admin_user(db: DAL) -> bool:
    """Create admin user in default tenant."""
    admin_email = "admin@localhost.local"
    admin_password = "admin123"

    print(f"\n[*] Initializing admin user: {admin_email}")

    # Check if admin already exists
    existing_admin = db(db.users.email == admin_email).select().first()
    if existing_admin:
        print(f"[!] Admin user already exists with ID: {existing_admin.id}")
        return False

    # Check or create default tenant
    default_tenant = db(db.tenants.slug == "default").select().first()
    if not default_tenant:
        print("[*] Creating default tenant...")
        tenant_id = db.tenants.insert(
            name="Default",
            slug="default",
            description="Default tenant for all users",
            is_active=True,
            max_users=0,
            max_repositories=0,
            max_teams=0,
            settings={},
        )
        db.commit()
        print(f"[+] Default tenant created with ID: {tenant_id}")

        # Create default team for this tenant
        print("[*] Creating default team...")
        team_id = db.teams.insert(
            tenant_id=tenant_id,
            name="Default",
            slug="default",
            description="Default team for all tenant members",
            is_active=True,
            is_default=True,
            settings={},
        )
        db.commit()
        print(f"[+] Default team created with ID: {team_id}")
    else:
        tenant_id = default_tenant.id
        print(f"[+] Using existing default tenant with ID: {tenant_id}")

        # Check if default team exists
        default_team = db(
            (db.teams.tenant_id == tenant_id) & (db.teams.is_default == True)
        ).select().first()
        if not default_team:
            print("[*] Creating default team...")
            team_id = db.teams.insert(
                tenant_id=tenant_id,
                name="Default",
                slug="default",
                description="Default team for all tenant members",
                is_active=True,
                is_default=True,
                settings={},
            )
            db.commit()
            print(f"[+] Default team created with ID: {team_id}")
        else:
            team_id = default_team.id
            print(f"[+] Using existing default team with ID: {team_id}")

    # Create admin user
    print(f"[*] Creating admin user: {admin_email}")
    user_id = db.users.insert(
        email=admin_email,
        password_hash=hash_password(admin_password),
        full_name="Administrator",
        role="admin",
        global_role="admin",
        default_tenant_id=tenant_id,
        is_active=True,
    )
    db.commit()
    print(f"[+] Admin user created with ID: {user_id}")

    # Add admin to default tenant
    print(f"[*] Adding admin to default tenant (ID: {tenant_id})...")
    tenant_member_id = db.tenant_members.insert(
        tenant_id=tenant_id,
        user_id=user_id,
        role="admin",
        is_active=True,
    )
    db.commit()
    print(f"[+] Admin added to tenant with membership ID: {tenant_member_id}")

    # Add admin to default team
    print(f"[*] Adding admin to default team (ID: {team_id})...")
    team_member_id = db.team_members.insert(
        team_id=team_id,
        user_id=user_id,
        role="admin",
        is_active=True,
    )
    db.commit()
    print(f"[+] Admin added to team with membership ID: {team_member_id}")

    return True


def main():
    """Main entry point."""
    print("=" * 60)
    print("Darwin Admin User Initialization Script")
    print("=" * 60)

    # Wait for database
    if not wait_for_database():
        print("\n[!] ERROR: Could not connect to database after maximum retries")
        sys.exit(1)

    try:
        # Initialize database
        print("\n[*] Initializing database connection...")
        db = init_db()
        print("[+] Database initialized")

        # Create admin user
        if create_admin_user(db):
            print("\n" + "=" * 60)
            print("[+] SUCCESS: Admin user initialized")
            print("=" * 60)
            print("\nAdmin Account Credentials:")
            print(f"  Email:    admin@localhost.local")
            print(f"  Password: admin123")
            print(f"\nTenant:     Default (ID: 1)")
            print(f"Team:       Default (ID: 1)")
            print("\nIMPORTANT: Change the default password immediately!")
            print("=" * 60)
        else:
            print("\n[!] Admin user already exists, no action taken")
            sys.exit(0)

    except Exception as e:
        print(f"\n[!] ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
