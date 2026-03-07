"""Pydantic models for PKI Server request/response validation."""

import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# =============================================================================
# Enums
# =============================================================================
class KeyAlgorithm(str, Enum):
    RSA = "RSA"
    ECDSA = "ECDSA"
    ED25519 = "ED25519"


class SSHKeyType(str, Enum):
    RSA = "rsa"
    ECDSA = "ecdsa"
    ED25519 = "ed25519"


class SSHCertificateType(str, Enum):
    USER = "user"
    HOST = "host"


class CertificateStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"


class RevocationReason(str, Enum):
    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key_compromise"
    CA_COMPROMISE = "ca_compromise"
    AFFILIATION_CHANGED = "affiliation_changed"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"
    CERTIFICATE_HOLD = "certificate_hold"
    REMOVE_FROM_CRL = "remove_from_crl"
    PRIVILEGE_WITHDRAWN = "privilege_withdrawn"


class KeyUsage(str, Enum):
    DIGITAL_SIGNATURE = "digital_signature"
    KEY_ENCIPHERMENT = "key_encipherment"
    DATA_ENCIPHERMENT = "data_encipherment"
    KEY_AGREEMENT = "key_agreement"
    KEY_CERT_SIGN = "key_cert_sign"
    CRL_SIGN = "crl_sign"
    ENCIPHER_ONLY = "encipher_only"
    DECIPHER_ONLY = "decipher_only"


class ExtendedKeyUsage(str, Enum):
    SERVER_AUTH = "server_auth"
    CLIENT_AUTH = "client_auth"
    CODE_SIGNING = "code_signing"
    EMAIL_PROTECTION = "email_protection"
    TIME_STAMPING = "time_stamping"
    OCSP_SIGNING = "ocsp_signing"


# =============================================================================
# X.509 Certificate Models
# =============================================================================
class X509CertificateRequest(BaseModel):
    """Request to issue an X.509 certificate."""

    subject: str = Field(
        ..., min_length=1, max_length=512, description="Certificate subject DN"
    )
    key_algorithm: KeyAlgorithm = Field(
        default=KeyAlgorithm.RSA, description="Key algorithm"
    )
    key_size: int = Field(
        default=4096, ge=2048, le=8192, description="Key size in bits (RSA/ECDSA)"
    )
    validity_days: int = Field(
        default=365, ge=1, le=825, description="Certificate validity in days"
    )
    san_dns: List[str] = Field(
        default_factory=list,
        max_length=50,
        description="Subject Alternative Names - DNS",
    )
    san_ip: List[str] = Field(
        default_factory=list,
        max_length=20,
        description="Subject Alternative Names - IP",
    )
    san_email: List[str] = Field(
        default_factory=list,
        max_length=10,
        description="Subject Alternative Names - Email",
    )
    key_usage: List[KeyUsage] = Field(
        default_factory=lambda: [KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT],
        description="Key usage extensions",
    )
    extended_key_usage: List[ExtendedKeyUsage] = Field(
        default_factory=lambda: [ExtendedKeyUsage.SERVER_AUTH],
        description="Extended key usage",
    )
    is_ca: bool = Field(default=False, description="Issue as CA certificate")
    path_length: Optional[int] = Field(
        default=None, ge=0, le=10, description="CA path length constraint"
    )
    csr_pem: Optional[str] = Field(
        default=None,
        description="CSR in PEM format (if provided, key is not generated)",
    )
    generate_key: bool = Field(
        default=True, description="Generate private key (ignored if CSR provided)"
    )

    @field_validator("san_dns", mode="before")
    @classmethod
    def validate_san_dns(cls, v: List[str]) -> List[str]:
        if not v:
            return v
        dns_pattern = re.compile(
            r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*" r"[a-zA-Z]{2,}$"
        )
        for dns in v:
            if not dns_pattern.match(dns):
                raise ValueError(f"Invalid DNS name: {dns}")
        return v

    @field_validator("san_ip", mode="before")
    @classmethod
    def validate_san_ip(cls, v: List[str]) -> List[str]:
        if not v:
            return v
        ipv4_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        ipv6_pattern = re.compile(
            r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
            r"^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$"
        )
        for ip in v:
            if not (ipv4_pattern.match(ip) or ipv6_pattern.match(ip)):
                raise ValueError(f"Invalid IP address: {ip}")
        return v

    @model_validator(mode="after")
    def validate_ca_constraints(self) -> "X509CertificateRequest":
        if self.is_ca and KeyUsage.KEY_CERT_SIGN not in self.key_usage:
            self.key_usage.append(KeyUsage.KEY_CERT_SIGN)
        if not self.is_ca and self.path_length is not None:
            raise ValueError("path_length only valid for CA certificates")
        return self


class X509CertificateResponse(BaseModel):
    """Response containing issued X.509 certificate."""

    id: str
    serial_number: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    key_algorithm: str
    key_size: Optional[int]
    fingerprint_sha256: str
    certificate_pem: str
    private_key_pem: Optional[str] = None
    chain_pem: Optional[str] = None
    san_dns: List[str] = []
    san_ip: List[str] = []
    status: CertificateStatus
    created_at: datetime


class X509CertificateInfo(BaseModel):
    """Certificate information without private key."""

    id: str
    serial_number: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    key_algorithm: str
    fingerprint_sha256: str
    san_dns: List[str] = []
    san_ip: List[str] = []
    status: CertificateStatus
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    created_at: datetime


# =============================================================================
# SSH Certificate Models
# =============================================================================
class SSHCertificateRequest(BaseModel):
    """Request to issue an SSH certificate."""

    public_key: str = Field(..., min_length=50, description="SSH public key")
    certificate_type: SSHCertificateType = Field(
        default=SSHCertificateType.USER, description="Certificate type (user or host)"
    )
    key_id: str = Field(..., min_length=1, max_length=256, description="Key identifier")
    principals: List[str] = Field(
        ..., min_length=1, max_length=50, description="List of principals"
    )
    validity_seconds: int = Field(
        default=86400, ge=60, le=604800, description="Validity period in seconds"
    )
    extensions: Dict[str, str] = Field(
        default_factory=lambda: {
            "permit-agent-forwarding": "",
            "permit-port-forwarding": "",
            "permit-pty": "",
            "permit-user-rc": "",
        },
        description="Certificate extensions",
    )
    critical_options: Dict[str, str] = Field(
        default_factory=dict, description="Critical options"
    )
    source_addresses: List[str] = Field(
        default_factory=list, description="Allowed source addresses"
    )
    force_command: Optional[str] = Field(
        default=None, max_length=512, description="Forced command"
    )
    hostname: Optional[str] = Field(
        default=None, max_length=256, description="Hostname for host certificates"
    )

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        if not v.startswith(("ssh-rsa", "ssh-ed25519", "ecdsa-sha2")):
            raise ValueError("Invalid SSH public key format")
        return v

    @field_validator("principals", mode="before")
    @classmethod
    def validate_principals(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("At least one principal required")
        principal_pattern = re.compile(r"^[a-zA-Z0-9._-]+$")
        for p in v:
            if not principal_pattern.match(p):
                raise ValueError(f"Invalid principal: {p}")
        return v

    @model_validator(mode="after")
    def validate_host_cert(self) -> "SSHCertificateRequest":
        if self.certificate_type == SSHCertificateType.HOST:
            if not self.hostname:
                raise ValueError("hostname required for host certificates")
            # Remove user extensions for host certs
            self.extensions = {}
        return self


class SSHCertificateResponse(BaseModel):
    """Response containing issued SSH certificate."""

    id: str
    serial_number: str
    key_id: str
    certificate_type: str
    principals: List[str]
    valid_after: datetime
    valid_before: datetime
    key_type: str
    certificate: str
    ca_public_key: str
    extensions: Dict[str, str] = {}
    critical_options: Dict[str, str] = {}
    status: CertificateStatus
    created_at: datetime


class SSHCertificateInfo(BaseModel):
    """SSH certificate information."""

    id: str
    serial_number: str
    key_id: str
    certificate_type: str
    principals: List[str]
    valid_after: datetime
    valid_before: datetime
    key_type: str
    hostname: Optional[str] = None
    status: CertificateStatus
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    created_at: datetime


# =============================================================================
# Revocation Models
# =============================================================================
class RevokeRequest(BaseModel):
    """Request to revoke a certificate."""

    reason: RevocationReason = Field(
        default=RevocationReason.UNSPECIFIED, description="Revocation reason"
    )
    invalidity_date: Optional[datetime] = Field(
        default=None, description="Date when key was compromised"
    )


class CRLResponse(BaseModel):
    """Certificate Revocation List response."""

    crl_number: int
    this_update: datetime
    next_update: datetime
    revoked_certificates: List[Dict[str, Any]]
    crl_pem: Optional[str] = None


class KRLResponse(BaseModel):
    """SSH Key Revocation List response."""

    version: int
    generated_at: datetime
    revoked_keys: List[Dict[str, Any]]
    krl_binary: Optional[str] = None  # Base64 encoded


# =============================================================================
# OCSP Models
# =============================================================================
class OCSPRequest(BaseModel):
    """OCSP request."""

    serial_number: str = Field(..., description="Certificate serial number")
    issuer_name_hash: Optional[str] = None
    issuer_key_hash: Optional[str] = None


class OCSPResponse(BaseModel):
    """OCSP response."""

    serial_number: str
    status: str  # good, revoked, unknown
    this_update: datetime
    next_update: datetime
    revocation_time: Optional[datetime] = None
    revocation_reason: Optional[str] = None


# =============================================================================
# CA Information Models
# =============================================================================
class CAInfo(BaseModel):
    """Certificate Authority information."""

    ca_type: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    serial_counter: int
    crl_number: int
    last_crl_update: Optional[datetime] = None
    next_crl_update: Optional[datetime] = None


class X509CAInfo(CAInfo):
    """X.509 CA specific information."""

    ca_certificate_pem: str
    ocsp_responder_url: Optional[str] = None
    crl_distribution_points: List[str] = []


class SSHCAInfo(BaseModel):
    """SSH CA information."""

    ca_public_key: str
    key_type: str
    fingerprint: str
    serial_counter: int
    krl_version: int


# =============================================================================
# Search and Filter Models
# =============================================================================
class CertificateSearchRequest(BaseModel):
    """Search certificates."""

    subject: Optional[str] = None
    serial_number: Optional[str] = None
    fingerprint: Optional[str] = None
    status: Optional[CertificateStatus] = None
    san_dns: Optional[str] = None
    issued_after: Optional[datetime] = None
    issued_before: Optional[datetime] = None
    expires_after: Optional[datetime] = None
    expires_before: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=100)


class CertificateListResponse(BaseModel):
    """Paginated certificate list."""

    certificates: List[X509CertificateInfo]
    total: int
    page: int
    page_size: int
    pages: int


class SSHCertificateListResponse(BaseModel):
    """Paginated SSH certificate list."""

    certificates: List[SSHCertificateInfo]
    total: int
    page: int
    page_size: int
    pages: int


# =============================================================================
# Statistics Models
# =============================================================================
class CertificateStatistics(BaseModel):
    """Certificate statistics."""

    total_certificates: int
    active_certificates: int
    revoked_certificates: int
    expired_certificates: int
    pending_certificates: int
    certificates_expiring_soon: int
    certificates_by_algorithm: Dict[str, int]
    certificates_issued_today: int
    certificates_issued_this_week: int
    certificates_issued_this_month: int


# =============================================================================
# Config Generation Models
# =============================================================================
class SSHConfigRequest(BaseModel):
    """Request to generate SSH config."""

    hostname: str = Field(..., description="Target hostname")
    port: int = Field(default=22, ge=1, le=65535)
    user: Optional[str] = None
    identity_file: Optional[str] = None


class SSHConfigResponse(BaseModel):
    """Generated SSH configuration."""

    ssh_config: str
    known_hosts_entry: str
    ca_public_key: str


class AuthorizedKeysRequest(BaseModel):
    """Request for authorized_keys generation."""

    principals: List[str] = Field(
        ..., min_length=1, description="Principals to authorize"
    )
    options: Dict[str, str] = Field(default_factory=dict, description="SSH options")


class AuthorizedKeysResponse(BaseModel):
    """Generated authorized_keys content."""

    authorized_keys: str
    trustedUserCAKeys: str
