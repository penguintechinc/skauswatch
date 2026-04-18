"""
Identity table definitions for native platform authentication.

penguin-dal table auto-reflection for identity management.
All PII (email, name, phone) is centralized in identity_users.
All other tables reference users by UUID only — no PII outside this module.

Tables (defined in Alembic migration, not here):
  identity_users       — canonical user identity with all PII
  identity_groups      — local and external groups
  identity_memberships — user-group membership with role
  identity_attributes  — key-value attributes for users and groups
  identity_sessions    — JWT session revocation via token hash
  identity_mfa_challenges — MFA challenge records (TOTP/backup)
"""

from penguin_dal import DB


# ---------------------------------------------------------------------------
# Valid values
# ---------------------------------------------------------------------------

def init_identity_tables(db_uri: str, pool_size: int = 10) -> DB:
    """
    Create and return a penguin-dal DB instance with identity tables.

    Tables are auto-reflected from the database schema (defined in Alembic
    migration). penguin-dal provides the same PyDAL-compatible query API
    while unifying schema definition under SQLAlchemy + Alembic.

    Args:
        db_uri: SQLAlchemy database connection URI.
        pool_size: Connection pool size (default 10).

    Returns:
        DB instance ready for queries.
    """
    return DB(db_uri, pool_size=pool_size)
