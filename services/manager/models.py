"""
Database models for SkausWatch Manager Service using pyDAL

This module defines all database models for the Manager service including:
- Users and authentication
- Roles and permissions (RBAC)
- Services configuration
- Certificate requests and lifecycle
- Audit logs
- System settings
"""

import datetime
import json
import logging
from typing import Any, Dict, List, Optional

from pydal import DAL, Field
from pydal.validators import (
    CLEANUP,
    CRYPT,
    IS_EMAIL,
    IS_IN_DB,
    IS_IN_SET,
    IS_JSON,
    IS_LENGTH,
    IS_MATCH,
    IS_NOT_EMPTY,
    IS_NOT_IN_DB,
    IS_SLUG,
)

logger = logging.getLogger(__name__)


class ManagerDatabase:
    """Database manager for SkausWatch Manager service"""

    def __init__(self, db_uri: str, migrate: bool = True, fake_migrate: bool = False):
        """Initialize database connection and define models
        
        Args:
            db_uri: Database connection string
            migrate: Enable database migrations
            fake_migrate: Enable fake migrations for testing
        """
        self.db = DAL(
            db_uri,
            migrate=migrate,
            fake_migrate=fake_migrate,
            lazy_tables=True,
            pool_size=10,
            check_reserved=["all"],
        )
        self._define_models()

    def _define_models(self) -> None:
        """Define all database models"""
        self._define_auth_models()
        self._define_service_models()
        self._define_certificate_models()
        self._define_audit_models()
        self._define_system_models()

    def _define_auth_models(self) -> None:
        """Define authentication and authorization models"""
        
        # Users table
        self.db.define_table(
            "auth_user",
            Field("id", "id"),
            Field("username", "string", length=64, unique=True, notnull=True,
                  requires=[IS_NOT_EMPTY(), IS_NOT_IN_DB(self.db, "auth_user.username"),
                           IS_MATCH(r"^[a-zA-Z0-9_-]{3,64}$")]),
            Field("email", "string", length=255, unique=True, notnull=True,
                  requires=[IS_EMAIL(), IS_NOT_IN_DB(self.db, "auth_user.email")]),
            Field("password", "password", length=512,
                  requires=[CRYPT(min_length=8), IS_LENGTH(8, 128)]),
            Field("first_name", "string", length=128, notnull=True,
                  requires=[IS_NOT_EMPTY(), IS_LENGTH(1, 128), CLEANUP()]),
            Field("last_name", "string", length=128, notnull=True,
                  requires=[IS_NOT_EMPTY(), IS_LENGTH(1, 128), CLEANUP()]),
            Field("is_active", "boolean", default=True, notnull=True),
            Field("is_superuser", "boolean", default=False, notnull=True),
            Field("last_login", "datetime"),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("updated_at", "datetime", update=datetime.datetime.utcnow, notnull=True),
            Field("password_changed_at", "datetime", default=datetime.datetime.utcnow),
            Field("failed_login_attempts", "integer", default=0, notnull=True),
            Field("account_locked_until", "datetime"),
            Field("mfa_enabled", "boolean", default=False, notnull=True),
            Field("mfa_secret", "string", length=32),
            Field("backup_codes", "json"),
            Field("session_timeout", "integer", default=3600),  # seconds
            migrate=True,
        )

        # Roles table
        self.db.define_table(
            "auth_role",
            Field("id", "id"),
            Field("name", "string", length=64, unique=True, notnull=True,
                  requires=[IS_NOT_EMPTY(), IS_NOT_IN_DB(self.db, "auth_role.name"),
                           IS_SLUG()]),
            Field("display_name", "string", length=128, notnull=True,
                  requires=[IS_NOT_EMPTY(), IS_LENGTH(1, 128)]),
            Field("description", "text"),
            Field("is_system", "boolean", default=False, notnull=True),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("updated_at", "datetime", update=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

        # Permissions table
        self.db.define_table(
            "auth_permission",
            Field("id", "id"),
            Field("name", "string", length=128, unique=True, notnull=True,
                  requires=[IS_NOT_EMPTY(), IS_NOT_IN_DB(self.db, "auth_permission.name")]),
            Field("resource", "string", length=64, notnull=True,
                  requires=[IS_NOT_EMPTY(), IS_MATCH(r"^[a-zA-Z0-9_]+$")]),
            Field("action", "string", length=64, notnull=True,
                  requires=[IS_NOT_EMPTY(), IS_IN_SET(
                      ["create", "read", "update", "delete", "execute", "admin"])]),
            Field("description", "text"),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

        # User-Role mapping
        self.db.define_table(
            "auth_user_role",
            Field("id", "id"),
            Field("user_id", "reference auth_user", notnull=True,
                  requires=IS_IN_DB(self.db, "auth_user.id", "auth_user.username")),
            Field("role_id", "reference auth_role", notnull=True,
                  requires=IS_IN_DB(self.db, "auth_role.id", "auth_role.display_name")),
            Field("granted_by", "reference auth_user",
                  requires=IS_IN_DB(self.db, "auth_user.id", "auth_user.username")),
            Field("granted_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("expires_at", "datetime"),
            migrate=True,
        )

        # Role-Permission mapping
        self.db.define_table(
            "auth_role_permission",
            Field("id", "id"),
            Field("role_id", "reference auth_role", notnull=True,
                  requires=IS_IN_DB(self.db, "auth_role.id", "auth_role.display_name")),
            Field("permission_id", "reference auth_permission", notnull=True,
                  requires=IS_IN_DB(self.db, "auth_permission.id", "auth_permission.name")),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

        # User sessions
        self.db.define_table(
            "auth_session",
            Field("id", "id"),
            Field("session_id", "string", length=128, unique=True, notnull=True),
            Field("user_id", "reference auth_user", notnull=True,
                  requires=IS_IN_DB(self.db, "auth_user.id", "auth_user.username")),
            Field("ip_address", "string", length=45),
            Field("user_agent", "text"),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("last_accessed", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("expires_at", "datetime", notnull=True),
            Field("is_active", "boolean", default=True, notnull=True),
            migrate=True,
        )

    def _define_service_models(self) -> None:
        """Define service configuration models"""
        
        # Service definitions
        self.db.define_table(
            "service",
            Field("id", "id"),
            Field("name", "string", length=64, unique=True, notnull=True,
                  requires=[IS_NOT_EMPTY(), IS_NOT_IN_DB(self.db, "service.name"),
                           IS_SLUG()]),
            Field("display_name", "string", length=128, notnull=True,
                  requires=[IS_NOT_EMPTY(), IS_LENGTH(1, 128)]),
            Field("description", "text"),
            Field("service_type", "string", length=32, notnull=True,
                  requires=IS_IN_SET(["manager", "pki-server", "ssh-ca", "aaa-monitor"])),
            Field("endpoint", "string", length=255,
                  requires=IS_MATCH(r"^https?://.+$")),
            Field("health_check_url", "string", length=255),
            Field("version", "string", length=32),
            Field("status", "string", length=16, default="unknown", notnull=True,
                  requires=IS_IN_SET(["healthy", "unhealthy", "degraded", "unknown"])),
            Field("last_health_check", "datetime"),
            Field("configuration", "json", default={}),
            Field("metadata", "json", default={}),
            Field("is_enabled", "boolean", default=True, notnull=True),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("updated_at", "datetime", update=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

        # Service configuration templates
        self.db.define_table(
            "service_config_template",
            Field("id", "id"),
            Field("name", "string", length=128, unique=True, notnull=True,
                  requires=[IS_NOT_EMPTY(), IS_NOT_IN_DB(self.db, "service_config_template.name")]),
            Field("service_type", "string", length=32, notnull=True,
                  requires=IS_IN_SET(["manager", "pki-server", "ssh-ca", "aaa-monitor"])),
            Field("template", "json", notnull=True, requires=IS_JSON()),
            Field("schema", "json", requires=IS_JSON()),
            Field("description", "text"),
            Field("version", "string", length=16, default="1.0"),
            Field("is_default", "boolean", default=False, notnull=True),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("updated_at", "datetime", update=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

    def _define_certificate_models(self) -> None:
        """Define certificate management models"""
        
        # Certificate requests
        self.db.define_table(
            "certificate_request",
            Field("id", "id"),
            Field("request_id", "string", length=128, unique=True, notnull=True),
            Field("requester_id", "reference auth_user", notnull=True,
                  requires=IS_IN_DB(self.db, "auth_user.id", "auth_user.username")),
            Field("certificate_type", "string", length=32, notnull=True,
                  requires=IS_IN_SET(["tls", "ssh", "client", "server", "ca"])),
            Field("common_name", "string", length=255, notnull=True,
                  requires=[IS_NOT_EMPTY(), IS_LENGTH(1, 255)]),
            Field("subject_alt_names", "json", default=[]),
            Field("key_algorithm", "string", length=16, default="rsa",
                  requires=IS_IN_SET(["rsa", "ec", "ed25519"])),
            Field("key_size", "integer", default=2048),
            Field("validity_days", "integer", default=365),
            Field("status", "string", length=16, default="pending", notnull=True,
                  requires=IS_IN_SET(["pending", "approved", "rejected", "issued", "revoked"])),
            Field("priority", "string", length=16, default="normal",
                  requires=IS_IN_SET(["low", "normal", "high", "critical"])),
            Field("purpose", "text"),
            Field("csr", "text"),  # Certificate Signing Request
            Field("certificate", "text"),  # Issued certificate
            Field("serial_number", "string", length=64),
            Field("issued_at", "datetime"),
            Field("expires_at", "datetime"),
            Field("revoked_at", "datetime"),
            Field("revocation_reason", "string", length=64),
            Field("approver_id", "reference auth_user"),
            Field("approved_at", "datetime"),
            Field("rejection_reason", "text"),
            Field("metadata", "json", default={}),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("updated_at", "datetime", update=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

        # Certificate inventory
        self.db.define_table(
            "certificate",
            Field("id", "id"),
            Field("serial_number", "string", length=64, unique=True, notnull=True),
            Field("common_name", "string", length=255, notnull=True),
            Field("issuer", "string", length=255),
            Field("certificate_type", "string", length=32, notnull=True,
                  requires=IS_IN_SET(["tls", "ssh", "client", "server", "ca"])),
            Field("pem_data", "text", notnull=True),
            Field("public_key", "text"),
            Field("key_algorithm", "string", length=16),
            Field("key_size", "integer"),
            Field("signature_algorithm", "string", length=32),
            Field("issued_at", "datetime", notnull=True),
            Field("expires_at", "datetime", notnull=True),
            Field("is_revoked", "boolean", default=False, notnull=True),
            Field("revoked_at", "datetime"),
            Field("revocation_reason", "string", length=64),
            Field("owner_id", "reference auth_user"),
            Field("service_id", "reference service"),
            Field("fingerprint_sha1", "string", length=40),
            Field("fingerprint_sha256", "string", length=64),
            Field("subject_alt_names", "json", default=[]),
            Field("extensions", "json", default={}),
            Field("metadata", "json", default={}),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("updated_at", "datetime", update=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

        # Approval workflows
        self.db.define_table(
            "approval_workflow",
            Field("id", "id"),
            Field("name", "string", length=128, unique=True, notnull=True),
            Field("resource_type", "string", length=32, notnull=True,
                  requires=IS_IN_SET(["certificate", "user", "service", "configuration"])),
            Field("conditions", "json", default={}),  # Conditions for triggering workflow
            Field("approvers", "json", default=[]),   # List of required approvers
            Field("approval_threshold", "integer", default=1),
            Field("auto_approve", "boolean", default=False),
            Field("timeout_hours", "integer", default=24),
            Field("is_active", "boolean", default=True, notnull=True),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("updated_at", "datetime", update=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

        # Approval requests
        self.db.define_table(
            "approval_request",
            Field("id", "id"),
            Field("workflow_id", "reference approval_workflow", notnull=True),
            Field("resource_id", "string", length=128, notnull=True),  # Generic reference
            Field("resource_type", "string", length=32, notnull=True),
            Field("requester_id", "reference auth_user", notnull=True),
            Field("status", "string", length=16, default="pending", notnull=True,
                  requires=IS_IN_SET(["pending", "approved", "rejected", "expired"])),
            Field("required_approvals", "integer", default=1),
            Field("current_approvals", "integer", default=0),
            Field("approvers", "json", default=[]),
            Field("approvals", "json", default=[]),
            Field("rejection_reason", "text"),
            Field("expires_at", "datetime", notnull=True),
            Field("completed_at", "datetime"),
            Field("metadata", "json", default={}),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("updated_at", "datetime", update=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

    def _define_audit_models(self) -> None:
        """Define audit logging models"""
        
        # Audit logs
        self.db.define_table(
            "audit_log",
            Field("id", "id"),
            Field("event_type", "string", length=64, notnull=True,
                  requires=IS_IN_SET([
                      "authentication", "authorization", "user_management",
                      "certificate_management", "configuration_change",
                      "service_operation", "system_event", "security_event"
                  ])),
            Field("action", "string", length=128, notnull=True),
            Field("resource_type", "string", length=64),
            Field("resource_id", "string", length=128),
            Field("user_id", "reference auth_user"),
            Field("session_id", "string", length=128),
            Field("ip_address", "string", length=45),
            Field("user_agent", "text"),
            Field("success", "boolean", notnull=True),
            Field("details", "json", default={}),
            Field("before_state", "json"),
            Field("after_state", "json"),
            Field("severity", "string", length=16, default="info",
                  requires=IS_IN_SET(["debug", "info", "warning", "error", "critical"])),
            Field("source_service", "string", length=64),
            Field("correlation_id", "string", length=128),
            Field("duration_ms", "integer"),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

        # Security events
        self.db.define_table(
            "security_event",
            Field("id", "id"),
            Field("event_category", "string", length=64, notnull=True,
                  requires=IS_IN_SET([
                      "authentication_failure", "authorization_failure",
                      "account_lockout", "privilege_escalation",
                      "suspicious_activity", "data_access", "configuration_change"
                  ])),
            Field("severity", "string", length=16, notnull=True,
                  requires=IS_IN_SET(["low", "medium", "high", "critical"])),
            Field("user_id", "reference auth_user"),
            Field("session_id", "string", length=128),
            Field("ip_address", "string", length=45),
            Field("user_agent", "text"),
            Field("description", "text", notnull=True),
            Field("details", "json", default={}),
            Field("risk_score", "integer", default=0),
            Field("is_resolved", "boolean", default=False),
            Field("resolved_by", "reference auth_user"),
            Field("resolved_at", "datetime"),
            Field("resolution_notes", "text"),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

    def _define_system_models(self) -> None:
        """Define system configuration and settings models"""
        
        # System settings
        self.db.define_table(
            "system_setting",
            Field("id", "id"),
            Field("category", "string", length=64, notnull=True,
                  requires=IS_IN_SET([
                      "authentication", "authorization", "certificates",
                      "security", "notifications", "system", "ui"
                  ])),
            Field("key", "string", length=128, notnull=True),
            Field("value", "json", default=None),
            Field("data_type", "string", length=16, default="string",
                  requires=IS_IN_SET(["string", "integer", "float", "boolean", "json"])),
            Field("description", "text"),
            Field("is_sensitive", "boolean", default=False),
            Field("is_readonly", "boolean", default=False),
            Field("validation_rules", "json"),
            Field("default_value", "json"),
            Field("updated_by", "reference auth_user"),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("updated_at", "datetime", update=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

        # Notification settings
        self.db.define_table(
            "notification_config",
            Field("id", "id"),
            Field("name", "string", length=128, unique=True, notnull=True),
            Field("event_types", "json", default=[], notnull=True),
            Field("channels", "json", default=[], notnull=True),
            Field("conditions", "json", default={}),
            Field("template", "text"),
            Field("is_enabled", "boolean", default=True, notnull=True),
            Field("created_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            Field("updated_at", "datetime", update=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

        # Health check results
        self.db.define_table(
            "health_check",
            Field("id", "id"),
            Field("service_id", "reference service", notnull=True),
            Field("check_type", "string", length=32, default="http",
                  requires=IS_IN_SET(["http", "tcp", "custom"])),
            Field("status", "string", length=16, notnull=True,
                  requires=IS_IN_SET(["healthy", "unhealthy", "timeout", "error"])),
            Field("response_time_ms", "integer"),
            Field("status_code", "integer"),
            Field("details", "json", default={}),
            Field("error_message", "text"),
            Field("checked_at", "datetime", default=datetime.datetime.utcnow, notnull=True),
            migrate=True,
        )

        # Add unique constraints
        self.db.commit()
        
        # Create indexes for performance
        self._create_indexes()

    def _create_indexes(self) -> None:
        """Create database indexes for performance"""
        try:
            # User authentication indexes
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_auth_user_username ON auth_user(username)")
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_auth_user_email ON auth_user(email)")
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_auth_session_session_id ON auth_session(session_id)")
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_auth_session_user_id ON auth_session(user_id)")
            
            # Certificate indexes
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_certificate_serial_number ON certificate(serial_number)")
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_certificate_expires_at ON certificate(expires_at)")
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_certificate_request_status ON certificate_request(status)")
            
            # Audit log indexes
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)")
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type)")
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)")
            
            # Service indexes
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_service_status ON service(status)")
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_health_check_service_id ON health_check(service_id)")
            self.db.executesql("CREATE INDEX IF NOT EXISTS idx_health_check_checked_at ON health_check(checked_at)")
            
            self.db.commit()
            logger.info("Database indexes created successfully")
        except Exception as e:
            logger.error(f"Failed to create indexes: {e}")

    def close(self) -> None:
        """Close database connection"""
        if hasattr(self, "db"):
            self.db.close()

    def get_tables(self) -> List[str]:
        """Get list of all table names"""
        return list(self.db.tables)

    def init_default_data(self) -> None:
        """Initialize database with default data"""
        try:
            # Create default system roles
            self._create_default_roles()
            
            # Create default permissions
            self._create_default_permissions()
            
            # Create default system settings
            self._create_default_settings()
            
            # Create default admin user if none exists
            self._create_default_admin()
            
            logger.info("Default data initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize default data: {e}")
            raise

    def _create_default_roles(self) -> None:
        """Create default system roles"""
        default_roles = [
            {
                "name": "superadmin",
                "display_name": "Super Administrator",
                "description": "Full system access with all permissions",
                "is_system": True,
            },
            {
                "name": "admin",
                "display_name": "Administrator",
                "description": "Administrative access to most system functions",
                "is_system": True,
            },
            {
                "name": "operator",
                "display_name": "System Operator",
                "description": "Operational access to services and monitoring",
                "is_system": True,
            },
            {
                "name": "user",
                "display_name": "Standard User",
                "description": "Basic user access with limited permissions",
                "is_system": True,
            },
            {
                "name": "auditor",
                "display_name": "Auditor",
                "description": "Read-only access for audit and compliance",
                "is_system": True,
            },
        ]

        for role_data in default_roles:
            existing = self.db(self.db.auth_role.name == role_data["name"]).select().first()
            if not existing:
                self.db.auth_role.insert(**role_data)

        self.db.commit()

    def _create_default_permissions(self) -> None:
        """Create default system permissions"""
        resources = [
            "users", "roles", "permissions", "services", "certificates",
            "audit_logs", "system_settings", "dashboard", "api"
        ]
        actions = ["create", "read", "update", "delete", "admin", "execute"]

        for resource in resources:
            for action in actions:
                name = f"{resource}:{action}"
                existing = self.db(self.db.auth_permission.name == name).select().first()
                if not existing:
                    self.db.auth_permission.insert(
                        name=name,
                        resource=resource,
                        action=action,
                        description=f"Allow {action} operations on {resource}",
                    )

        self.db.commit()

    def _create_default_settings(self) -> None:
        """Create default system settings"""
        default_settings = [
            # Authentication settings
            {
                "category": "authentication",
                "key": "session_timeout",
                "value": 3600,
                "data_type": "integer",
                "description": "Default session timeout in seconds",
            },
            {
                "category": "authentication",
                "key": "password_min_length",
                "value": 8,
                "data_type": "integer",
                "description": "Minimum password length",
            },
            {
                "category": "authentication",
                "key": "mfa_required",
                "value": False,
                "data_type": "boolean",
                "description": "Require MFA for all users",
            },
            {
                "category": "authentication",
                "key": "max_login_attempts",
                "value": 5,
                "data_type": "integer",
                "description": "Maximum failed login attempts before lockout",
            },
            # Certificate settings
            {
                "category": "certificates",
                "key": "default_validity_days",
                "value": 365,
                "data_type": "integer",
                "description": "Default certificate validity period in days",
            },
            {
                "category": "certificates",
                "key": "auto_renewal_threshold_days",
                "value": 30,
                "data_type": "integer",
                "description": "Days before expiry to trigger auto-renewal",
            },
            # Security settings
            {
                "category": "security",
                "key": "audit_retention_days",
                "value": 365,
                "data_type": "integer",
                "description": "Audit log retention period in days",
            },
            {
                "category": "security",
                "key": "rate_limit_requests_per_minute",
                "value": 60,
                "data_type": "integer",
                "description": "API rate limit per minute per user",
            },
        ]

        for setting in default_settings:
            # Check if setting already exists (by category + key combination)
            existing = self.db(
                (self.db.system_setting.category == setting["category"]) &
                (self.db.system_setting.key == setting["key"])
            ).select().first()
            
            if not existing:
                self.db.system_setting.insert(**setting)

        self.db.commit()

    def _create_default_admin(self) -> None:
        """Create default admin user if no users exist"""
        user_count = self.db(self.db.auth_user).count()
        if user_count == 0:
            # Create default admin user
            admin_id = self.db.auth_user.insert(
                username="admin",
                email="admin@skauswatch.local",
                password="admin123!",  # This will be hashed by CRYPT validator
                first_name="System",
                last_name="Administrator",
                is_superuser=True,
                is_active=True,
            )

            # Assign superadmin role
            superadmin_role = self.db(self.db.auth_role.name == "superadmin").select().first()
            if superadmin_role:
                self.db.auth_user_role.insert(
                    user_id=admin_id,
                    role_id=superadmin_role.id,
                    granted_by=admin_id,
                )

            self.db.commit()
            logger.info("Default admin user created (username: admin, password: admin123!)")


# Database connection management
_db_instance: Optional[ManagerDatabase] = None


def get_database(db_uri: str = None, **kwargs) -> ManagerDatabase:
    """Get database instance (singleton)"""
    global _db_instance
    
    if _db_instance is None:
        if db_uri is None:
            raise ValueError("Database URI must be provided for first initialization")
        _db_instance = ManagerDatabase(db_uri, **kwargs)
    
    return _db_instance


def close_database() -> None:
    """Close database connection"""
    global _db_instance
    if _db_instance:
        _db_instance.close()
        _db_instance = None