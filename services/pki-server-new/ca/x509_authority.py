"""X.509 Certificate Authority implementation."""

import hashlib
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.x509 import (
    CertificateBuilder,
    CertificateRevocationListBuilder,
    RevokedCertificateBuilder,
    NameOID,
    ExtensionOID,
)
from cryptography.x509.oid import ExtendedKeyUsageOID
import structlog

from ..config import X509CAConfig

logger = structlog.get_logger()


class X509CertificateAuthority:
    """X.509 Certificate Authority for issuing and managing certificates."""

    REVOCATION_REASONS = {
        "unspecified": x509.ReasonFlags.unspecified,
        "key_compromise": x509.ReasonFlags.key_compromise,
        "ca_compromise": x509.ReasonFlags.ca_compromise,
        "affiliation_changed": x509.ReasonFlags.affiliation_changed,
        "superseded": x509.ReasonFlags.superseded,
        "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
        "certificate_hold": x509.ReasonFlags.certificate_hold,
        "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    }

    KEY_USAGE_MAP = {
        "digital_signature": "digital_signature",
        "key_encipherment": "key_encipherment",
        "data_encipherment": "data_encipherment",
        "key_agreement": "key_agreement",
        "key_cert_sign": "key_cert_sign",
        "crl_sign": "crl_sign",
        "encipher_only": "encipher_only",
        "decipher_only": "decipher_only",
    }

    EKU_MAP = {
        "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
        "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
        "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
        "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
        "time_stamping": ExtendedKeyUsageOID.TIME_STAMPING,
        "ocsp_signing": ExtendedKeyUsageOID.OCSP_SIGNING,
    }

    def __init__(self, config: X509CAConfig):
        """Initialize X.509 CA."""
        self.config = config
        self._ca_key = None
        self._ca_cert = None
        self._serial_counter = 1
        self._crl_number = 0

    async def initialize(self) -> None:
        """Load or generate CA key and certificate."""
        ca_key_path = Path(self.config.ca_key_path)
        ca_cert_path = Path(self.config.ca_cert_path)

        if ca_key_path.exists() and ca_cert_path.exists():
            await self._load_ca()
        else:
            logger.warning("CA key/cert not found, generating new CA")
            await self._generate_ca()

        logger.info(
            "X.509 CA initialized",
            subject=self._ca_cert.subject.rfc4514_string() if self._ca_cert else None,
        )

    async def _load_ca(self) -> None:
        """Load existing CA key and certificate."""
        password = None
        if self.config.ca_key_password:
            password = self.config.ca_key_password.encode()

        with open(self.config.ca_key_path, "rb") as f:
            self._ca_key = serialization.load_pem_private_key(
                f.read(), password=password, backend=default_backend()
            )

        with open(self.config.ca_cert_path, "rb") as f:
            self._ca_cert = x509.load_pem_x509_certificate(
                f.read(), backend=default_backend()
            )

    async def _generate_ca(self) -> None:
        """Generate new CA key and self-signed certificate."""
        # Generate CA private key
        self._ca_key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )

        # Build CA certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SkausWatch"),
                x509.NameAttribute(NameOID.COMMON_NAME, "SkausWatch Root CA"),
            ]
        )

        self._ca_cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._ca_key.public_key()),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256(), backend=default_backend())
        )

        # Save CA key and certificate
        self._save_ca()

    def _save_ca(self) -> None:
        """Save CA key and certificate to disk."""
        ca_key_path = Path(self.config.ca_key_path)
        ca_cert_path = Path(self.config.ca_cert_path)

        # Ensure directory exists
        ca_key_path.parent.mkdir(parents=True, exist_ok=True)

        encryption = serialization.NoEncryption()
        if self.config.ca_key_password:
            encryption = serialization.BestAvailableEncryption(
                self.config.ca_key_password.encode()
            )

        with open(ca_key_path, "wb") as f:
            f.write(
                self._ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption,
                )
            )

        with open(ca_cert_path, "wb") as f:
            f.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))

        # Set permissions
        os.chmod(ca_key_path, 0o600)
        os.chmod(ca_cert_path, 0o644)

    def _generate_key(self, algorithm: str, key_size: int) -> Any:
        """Generate a private key."""
        algorithm = algorithm.upper()

        if algorithm == "RSA":
            return rsa.generate_private_key(
                public_exponent=65537, key_size=key_size, backend=default_backend()
            )
        elif algorithm == "ECDSA":
            if key_size <= 256:
                curve = ec.SECP256R1()
            elif key_size <= 384:
                curve = ec.SECP384R1()
            else:
                curve = ec.SECP521R1()
            return ec.generate_private_key(curve, backend=default_backend())
        elif algorithm == "ED25519":
            return ed25519.Ed25519PrivateKey.generate()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    def _get_next_serial(self) -> int:
        """Get next serial number."""
        serial = self._serial_counter
        self._serial_counter += 1
        return serial

    def _build_subject(self, subject_str: str) -> x509.Name:
        """Build X.509 Name from string."""
        # Parse DN string like "CN=example.com,O=Example,C=US"
        attrs = []
        for part in subject_str.split(","):
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.strip().upper()
                value = value.strip()

                oid_map = {
                    "CN": NameOID.COMMON_NAME,
                    "O": NameOID.ORGANIZATION_NAME,
                    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
                    "C": NameOID.COUNTRY_NAME,
                    "ST": NameOID.STATE_OR_PROVINCE_NAME,
                    "L": NameOID.LOCALITY_NAME,
                    "E": NameOID.EMAIL_ADDRESS,
                }

                if key in oid_map:
                    attrs.append(x509.NameAttribute(oid_map[key], value))

        if not attrs:
            # Default to CN if parsing fails
            attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, subject_str))

        return x509.Name(attrs)

    async def issue_certificate(
        self,
        subject: str,
        key_algorithm: str = "RSA",
        key_size: int = 4096,
        validity_days: int = 365,
        san_dns: List[str] = None,
        san_ip: List[str] = None,
        san_email: List[str] = None,
        key_usage: List[str] = None,
        extended_key_usage: List[str] = None,
        is_ca: bool = False,
        path_length: Optional[int] = None,
        csr_pem: Optional[str] = None,
    ) -> Tuple[str, str, Optional[str], Dict[str, Any]]:
        """
        Issue a new X.509 certificate.

        Returns:
            Tuple of (certificate_pem, serial_number, private_key_pem, metadata)
        """
        san_dns = san_dns or []
        san_ip = san_ip or []
        san_email = san_email or []
        key_usage = key_usage or ["digital_signature", "key_encipherment"]
        extended_key_usage = extended_key_usage or ["server_auth"]

        # Validate validity
        if validity_days > self.config.max_validity_days:
            validity_days = self.config.max_validity_days

        private_key = None
        private_key_pem = None
        public_key = None

        if csr_pem:
            # Parse CSR
            csr = x509.load_pem_x509_csr(csr_pem.encode(), backend=default_backend())
            public_key = csr.public_key()
        else:
            # Generate new key pair
            private_key = self._generate_key(key_algorithm, key_size)
            public_key = private_key.public_key()
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode()

        # Build certificate
        subject_name = self._build_subject(subject)
        serial_number = self._get_next_serial()

        not_before = datetime.utcnow()
        not_after = not_before + timedelta(days=validity_days)

        builder = (
            CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(self._ca_cert.subject)
            .public_key(public_key)
            .serial_number(serial_number)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )

        # Add Basic Constraints
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length),
            critical=True,
        )

        # Add Key Usage
        ku_kwargs = {k: False for k in self.KEY_USAGE_MAP.values()}
        for usage in key_usage:
            if usage in self.KEY_USAGE_MAP:
                ku_kwargs[self.KEY_USAGE_MAP[usage]] = True

        builder = builder.add_extension(
            x509.KeyUsage(**ku_kwargs),
            critical=True,
        )

        # Add Extended Key Usage
        eku_oids = []
        for eku in extended_key_usage:
            if eku in self.EKU_MAP:
                eku_oids.append(self.EKU_MAP[eku])

        if eku_oids:
            builder = builder.add_extension(
                x509.ExtendedKeyUsage(eku_oids),
                critical=False,
            )

        # Add Subject Alternative Names
        san_list = []
        for dns in san_dns:
            san_list.append(x509.DNSName(dns))
        for ip in san_ip:
            from ipaddress import ip_address

            san_list.append(x509.IPAddress(ip_address(ip)))
        for email in san_email:
            san_list.append(x509.RFC822Name(email))

        if san_list:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False,
            )

        # Add Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )

        # Add Authority Key Identifier
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self._ca_key.public_key()
            ),
            critical=False,
        )

        # Sign the certificate
        if key_algorithm.upper() == "ED25519":
            certificate = builder.sign(self._ca_key, None, backend=default_backend())
        else:
            certificate = builder.sign(
                self._ca_key, hashes.SHA256(), backend=default_backend()
            )

        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()

        # Calculate fingerprint
        fingerprint = hashlib.sha256(
            certificate.public_bytes(serialization.Encoding.DER)
        ).hexdigest()

        metadata = {
            "serial_number": format(serial_number, "x"),
            "subject": subject_name.rfc4514_string(),
            "issuer": self._ca_cert.subject.rfc4514_string(),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "fingerprint_sha256": fingerprint,
            "key_algorithm": key_algorithm,
            "key_size": key_size if key_algorithm != "ED25519" else None,
            "san_dns": san_dns,
            "san_ip": san_ip,
            "san_email": san_email,
            "is_ca": is_ca,
        }

        logger.info(
            "Certificate issued",
            serial=metadata["serial_number"],
            subject=subject,
            validity_days=validity_days,
        )

        return cert_pem, metadata["serial_number"], private_key_pem, metadata

    async def generate_crl(
        self, revoked_entries: List[Dict[str, Any]]
    ) -> Tuple[str, int]:
        """
        Generate a Certificate Revocation List.

        Args:
            revoked_entries: List of dicts with serial_number, revoked_at, reason

        Returns:
            Tuple of (crl_pem, crl_number)
        """
        self._crl_number += 1

        builder = CertificateRevocationListBuilder()
        builder = builder.issuer_name(self._ca_cert.subject)
        builder = builder.last_update(datetime.utcnow())
        builder = builder.next_update(
            datetime.utcnow() + timedelta(days=self.config.crl_validity_days)
        )

        # Add revoked certificates
        for entry in revoked_entries:
            serial = int(entry["serial_number"], 16)
            revoked_at = entry["revoked_at"]
            reason = entry.get("reason", "unspecified")

            revoked_builder = (
                RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(revoked_at)
            )

            if reason in self.REVOCATION_REASONS:
                revoked_builder = revoked_builder.add_extension(
                    x509.CRLReason(self.REVOCATION_REASONS[reason]), critical=False
                )

            builder = builder.add_revoked_certificate(revoked_builder.build())

        # Add CRL Number extension
        builder = builder.add_extension(
            x509.CRLNumber(self._crl_number), critical=False
        )

        # Sign the CRL
        crl = builder.sign(self._ca_key, hashes.SHA256(), backend=default_backend())

        crl_pem = crl.public_bytes(serialization.Encoding.PEM).decode()

        logger.info(
            "CRL generated",
            crl_number=self._crl_number,
            revoked_count=len(revoked_entries),
        )

        return crl_pem, self._crl_number

    def get_ca_certificate_pem(self) -> str:
        """Get CA certificate in PEM format."""
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    def get_ca_info(self) -> Dict[str, Any]:
        """Get CA information."""
        fingerprint = hashlib.sha256(
            self._ca_cert.public_bytes(serialization.Encoding.DER)
        ).hexdigest()

        return {
            "subject": self._ca_cert.subject.rfc4514_string(),
            "issuer": self._ca_cert.issuer.rfc4514_string(),
            "not_before": self._ca_cert.not_valid_before_utc.isoformat(),
            "not_after": self._ca_cert.not_valid_after_utc.isoformat(),
            "fingerprint_sha256": fingerprint,
            "serial_counter": self._serial_counter,
            "crl_number": self._crl_number,
        }

    def verify_certificate(self, cert_pem: str) -> bool:
        """Verify a certificate was issued by this CA."""
        try:
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(), backend=default_backend()
            )
            # Check if issuer matches CA
            if cert.issuer != self._ca_cert.subject:
                return False
            # Verify signature
            self._ca_key.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_parameters,
            )
            return True
        except Exception:
            return False
