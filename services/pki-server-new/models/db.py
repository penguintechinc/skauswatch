"""Database initialization and runtime operations.

SQLAlchemy: Used ONLY for database initialization and schema creation.
PyDAL: Used for ALL runtime database operations.
"""
import os
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Generator, Optional

from pydal import DAL, Field
from pydal.validators import (
    IS_IN_SET, IS_NOT_EMPTY, IS_DATETIME, IS_INT_IN_RANGE
)
from sqlalchemy import (
    create_engine, MetaData, Table, Column, String, Boolean, DateTime,
    Integer, Text, LargeBinary, ForeignKey, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
import uuid


# Thread-local storage for PyDAL connections
_thread_local = threading.local()


# =============================================================================
# SQLAlchemy: DATABASE INITIALIZATION ONLY
# =============================================================================
def init_database_schema(database_url: str) -> None:
    """
    Initialize database schema using SQLAlchemy.
    Called ONCE at application startup if tables don't exist.
    DO NOT use SQLAlchemy for any runtime operations.
    """
    engine = create_engine(database_url)
    metadata = MetaData()

    # X.509 Certificates table
    Table(
        "x509_certificates", metadata,
        Column("id", UUID, primary_key=True, default=uuid.uuid4),
        Column("serial_number", String(64), unique=True, nullable=False),
        Column("subject", String(512), nullable=False),
        Column("issuer", String(512), nullable=False),
        Column("not_before", DateTime, nullable=False),
        Column("not_after", DateTime, nullable=False),
        Column("key_algorithm", String(20), nullable=False),
        Column("key_size", Integer),
        Column("signature_algorithm", String(50), nullable=False),
        Column("fingerprint_sha256", String(64), nullable=False),
        Column("certificate_pem", Text, nullable=False),
        Column("private_key_pem", Text),  # Encrypted if stored
        Column("csr_pem", Text),
        Column("san_dns", ARRAY(String)),
        Column("san_ip", ARRAY(String)),
        Column("san_email", ARRAY(String)),
        Column("key_usage", ARRAY(String)),
        Column("extended_key_usage", ARRAY(String)),
        Column("is_ca", Boolean, default=False),
        Column("path_length", Integer),
        Column("status", String(20), default="active"),
        Column("revoked_at", DateTime),
        Column("revocation_reason", String(50)),
        Column("requester_id", UUID),
        Column("approver_id", UUID),
        Column("approval_request_id", UUID),
        Column("metadata", JSONB, default={}),
        Column("created_at", DateTime, server_default="now()"),
        Column("updated_at", DateTime, server_default="now()"),
        Index("idx_x509_serial", "serial_number"),
        Index("idx_x509_fingerprint", "fingerprint_sha256"),
        Index("idx_x509_subject", "subject"),
        Index("idx_x509_status", "status"),
        Index("idx_x509_not_after", "not_after"),
    )

    # SSH Certificates table
    Table(
        "ssh_certificates", metadata,
        Column("id", UUID, primary_key=True, default=uuid.uuid4),
        Column("serial_number", String(64), unique=True, nullable=False),
        Column("key_id", String(256), nullable=False),
        Column("certificate_type", String(10), nullable=False),  # user/host
        Column("principals", ARRAY(String), nullable=False),
        Column("valid_after", DateTime, nullable=False),
        Column("valid_before", DateTime, nullable=False),
        Column("key_type", String(20), nullable=False),
        Column("public_key", Text, nullable=False),
        Column("certificate", Text, nullable=False),
        Column("critical_options", JSONB, default={}),
        Column("extensions", JSONB, default={}),
        Column("source_address", ARRAY(String)),
        Column("force_command", String(512)),
        Column("status", String(20), default="active"),
        Column("revoked_at", DateTime),
        Column("revocation_reason", String(50)),
        Column("requester_id", UUID),
        Column("approver_id", UUID),
        Column("approval_request_id", UUID),
        Column("hostname", String(256)),
        Column("metadata", JSONB, default={}),
        Column("created_at", DateTime, server_default="now()"),
        Column("updated_at", DateTime, server_default="now()"),
        Index("idx_ssh_serial", "serial_number"),
        Index("idx_ssh_key_id", "key_id"),
        Index("idx_ssh_principals", "principals"),
        Index("idx_ssh_status", "status"),
        Index("idx_ssh_valid_before", "valid_before"),
    )

    # Certificate Revocation List (CRL) entries
    Table(
        "crl_entries", metadata,
        Column("id", UUID, primary_key=True, default=uuid.uuid4),
        Column("certificate_id", UUID, nullable=False),
        Column("serial_number", String(64), nullable=False),
        Column("certificate_type", String(10), nullable=False),  # x509/ssh
        Column("revoked_at", DateTime, nullable=False),
        Column("revocation_reason", String(50), nullable=False),
        Column("invalidity_date", DateTime),
        Column("crl_number", Integer),
        Column("created_at", DateTime, server_default="now()"),
        Index("idx_crl_serial", "serial_number"),
        Index("idx_crl_type", "certificate_type"),
    )

    # Audit log for PKI operations
    Table(
        "pki_audit_log", metadata,
        Column("id", UUID, primary_key=True, default=uuid.uuid4),
        Column("event_type", String(50), nullable=False),
        Column("certificate_type", String(10)),  # x509/ssh
        Column("certificate_id", UUID),
        Column("serial_number", String(64)),
        Column("subject", String(512)),
        Column("actor_id", UUID),
        Column("actor_ip", String(45)),
        Column("action", String(50), nullable=False),
        Column("status", String(20), nullable=False),  # success/failure
        Column("error_message", Text),
        Column("request_data", JSONB),
        Column("response_data", JSONB),
        Column("timestamp", DateTime, server_default="now()"),
        Index("idx_pki_audit_event", "event_type"),
        Index("idx_pki_audit_cert_id", "certificate_id"),
        Index("idx_pki_audit_timestamp", "timestamp"),
    )

    # CA Configuration and state
    Table(
        "ca_state", metadata,
        Column("id", UUID, primary_key=True, default=uuid.uuid4),
        Column("ca_type", String(10), nullable=False),  # x509/ssh
        Column("serial_counter", Integer, default=1),
        Column("crl_number", Integer, default=0),
        Column("last_crl_update", DateTime),
        Column("next_crl_update", DateTime),
        Column("ca_fingerprint", String(64)),
        Column("ca_subject", String(512)),
        Column("ca_not_before", DateTime),
        Column("ca_not_after", DateTime),
        Column("created_at", DateTime, server_default="now()"),
        Column("updated_at", DateTime, server_default="now()"),
    )

    # Create all tables
    metadata.create_all(engine)
    engine.dispose()


# =============================================================================
# PyDAL: ALL RUNTIME OPERATIONS
# =============================================================================
def get_db() -> DAL:
    """Get thread-local PyDAL connection for runtime operations."""
    if not hasattr(_thread_local, "db"):
        db_url = os.getenv(
            "DATABASE_URL",
            "postgresql://skauswatch:password@localhost:5432/skauswatch"
        )
        _thread_local.db = DAL(
            db_url,
            migrate=False,  # Schema managed by SQLAlchemy init
            pool_size=10
        )
        define_pydal_tables(_thread_local.db)
    return _thread_local.db


def define_pydal_tables(db: DAL) -> None:
    """Define PyDAL table definitions for runtime use."""

    # X.509 Certificates
    db.define_table(
        "x509_certificates",
        Field("serial_number", "string", length=64, required=True),
        Field("subject", "string", length=512, required=True),
        Field("issuer", "string", length=512, required=True),
        Field("not_before", "datetime", required=True),
        Field("not_after", "datetime", required=True),
        Field("key_algorithm", "string", length=20,
              requires=IS_IN_SET(["RSA", "ECDSA", "ED25519"])),
        Field("key_size", "integer"),
        Field("signature_algorithm", "string", length=50),
        Field("fingerprint_sha256", "string", length=64, required=True),
        Field("certificate_pem", "text", required=True),
        Field("private_key_pem", "text"),
        Field("csr_pem", "text"),
        Field("san_dns", "list:string"),
        Field("san_ip", "list:string"),
        Field("san_email", "list:string"),
        Field("key_usage", "list:string"),
        Field("extended_key_usage", "list:string"),
        Field("is_ca", "boolean", default=False),
        Field("path_length", "integer"),
        Field("status", "string", length=20, default="active",
              requires=IS_IN_SET(["active", "revoked", "expired", "pending"])),
        Field("revoked_at", "datetime"),
        Field("revocation_reason", "string", length=50),
        Field("requester_id", "string", length=36),
        Field("approver_id", "string", length=36),
        Field("approval_request_id", "string", length=36),
        Field("metadata", "json", default={}),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow),
        migrate=False
    )

    # SSH Certificates
    db.define_table(
        "ssh_certificates",
        Field("serial_number", "string", length=64, required=True),
        Field("key_id", "string", length=256, required=True),
        Field("certificate_type", "string", length=10,
              requires=IS_IN_SET(["user", "host"])),
        Field("principals", "list:string", required=True),
        Field("valid_after", "datetime", required=True),
        Field("valid_before", "datetime", required=True),
        Field("key_type", "string", length=20,
              requires=IS_IN_SET(["rsa", "ecdsa", "ed25519"])),
        Field("public_key", "text", required=True),
        Field("certificate", "text", required=True),
        Field("critical_options", "json", default={}),
        Field("extensions", "json", default={}),
        Field("source_address", "list:string"),
        Field("force_command", "string", length=512),
        Field("status", "string", length=20, default="active",
              requires=IS_IN_SET(["active", "revoked", "expired"])),
        Field("revoked_at", "datetime"),
        Field("revocation_reason", "string", length=50),
        Field("requester_id", "string", length=36),
        Field("approver_id", "string", length=36),
        Field("approval_request_id", "string", length=36),
        Field("hostname", "string", length=256),
        Field("metadata", "json", default={}),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow),
        migrate=False
    )

    # CRL Entries
    db.define_table(
        "crl_entries",
        Field("certificate_id", "string", length=36, required=True),
        Field("serial_number", "string", length=64, required=True),
        Field("certificate_type", "string", length=10,
              requires=IS_IN_SET(["x509", "ssh"])),
        Field("revoked_at", "datetime", required=True),
        Field("revocation_reason", "string", length=50,
              requires=IS_IN_SET([
                  "unspecified", "key_compromise", "ca_compromise",
                  "affiliation_changed", "superseded", "cessation_of_operation",
                  "certificate_hold", "remove_from_crl", "privilege_withdrawn"
              ])),
        Field("invalidity_date", "datetime"),
        Field("crl_number", "integer"),
        Field("created_at", "datetime", default=datetime.utcnow),
        migrate=False
    )

    # PKI Audit Log
    db.define_table(
        "pki_audit_log",
        Field("event_type", "string", length=50, required=True),
        Field("certificate_type", "string", length=10),
        Field("certificate_id", "string", length=36),
        Field("serial_number", "string", length=64),
        Field("subject", "string", length=512),
        Field("actor_id", "string", length=36),
        Field("actor_ip", "string", length=45),
        Field("action", "string", length=50, required=True),
        Field("status", "string", length=20,
              requires=IS_IN_SET(["success", "failure"])),
        Field("error_message", "text"),
        Field("request_data", "json"),
        Field("response_data", "json"),
        Field("timestamp", "datetime", default=datetime.utcnow),
        migrate=False
    )

    # CA State
    db.define_table(
        "ca_state",
        Field("ca_type", "string", length=10,
              requires=IS_IN_SET(["x509", "ssh"])),
        Field("serial_counter", "integer", default=1),
        Field("crl_number", "integer", default=0),
        Field("last_crl_update", "datetime"),
        Field("next_crl_update", "datetime"),
        Field("ca_fingerprint", "string", length=64),
        Field("ca_subject", "string", length=512),
        Field("ca_not_before", "datetime"),
        Field("ca_not_after", "datetime"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow),
        migrate=False
    )


@contextmanager
def db_session() -> Generator[DAL, None, None]:
    """Context manager for database sessions with automatic commit/rollback."""
    db = get_db()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise


def close_db() -> None:
    """Close the thread-local database connection."""
    if hasattr(_thread_local, "db"):
        _thread_local.db.close()
        del _thread_local.db
