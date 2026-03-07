"""Certificate management service."""

import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import structlog

from ..ca import SSHCertificateAuthority, X509CertificateAuthority
from ..models.db import db_session, get_db

logger = structlog.get_logger()


class CertificateManager:
    """Manages certificate lifecycle and database operations."""

    def __init__(
        self, x509_ca: X509CertificateAuthority, ssh_ca: SSHCertificateAuthority
    ):
        """Initialize certificate manager."""
        self.x509_ca = x509_ca
        self.ssh_ca = ssh_ca

    # =========================================================================
    # X.509 Certificate Operations
    # =========================================================================
    async def issue_x509_certificate(
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
        requester_id: Optional[str] = None,
        approval_request_id: Optional[str] = None,
        metadata: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Issue X.509 certificate and store in database."""
        cert_pem, serial, private_key_pem, cert_meta = (
            await self.x509_ca.issue_certificate(
                subject=subject,
                key_algorithm=key_algorithm,
                key_size=key_size,
                validity_days=validity_days,
                san_dns=san_dns,
                san_ip=san_ip,
                san_email=san_email,
                key_usage=key_usage,
                extended_key_usage=extended_key_usage,
                is_ca=is_ca,
                path_length=path_length,
                csr_pem=csr_pem,
            )
        )

        # Store in database
        with db_session() as db:
            cert_id = str(uuid.uuid4())
            not_before = datetime.fromisoformat(cert_meta["not_before"])
            not_after = datetime.fromisoformat(cert_meta["not_after"])

            db.x509_certificates.insert(
                id=cert_id,
                serial_number=serial,
                subject=cert_meta["subject"],
                issuer=cert_meta["issuer"],
                not_before=not_before,
                not_after=not_after,
                key_algorithm=key_algorithm,
                key_size=key_size if key_algorithm != "ED25519" else None,
                signature_algorithm="SHA256",
                fingerprint_sha256=cert_meta["fingerprint_sha256"],
                certificate_pem=cert_pem,
                private_key_pem=private_key_pem,
                csr_pem=csr_pem,
                san_dns=san_dns or [],
                san_ip=san_ip or [],
                san_email=san_email or [],
                key_usage=key_usage or [],
                extended_key_usage=extended_key_usage or [],
                is_ca=is_ca,
                path_length=path_length,
                status="active",
                requester_id=requester_id,
                approval_request_id=approval_request_id,
                metadata=metadata or {},
            )

            # Log audit event
            self._log_audit(
                db=db,
                event_type="certificate_issued",
                certificate_type="x509",
                certificate_id=cert_id,
                serial_number=serial,
                subject=cert_meta["subject"],
                action="issue",
                status="success",
            )

        return {
            "id": cert_id,
            "serial_number": serial,
            "subject": cert_meta["subject"],
            "issuer": cert_meta["issuer"],
            "not_before": not_before,
            "not_after": not_after,
            "key_algorithm": key_algorithm,
            "key_size": key_size,
            "fingerprint_sha256": cert_meta["fingerprint_sha256"],
            "certificate_pem": cert_pem,
            "private_key_pem": private_key_pem,
            "san_dns": san_dns or [],
            "san_ip": san_ip or [],
            "status": "active",
            "created_at": datetime.utcnow(),
        }

    async def get_x509_certificate(
        self, cert_id: str = None, serial_number: str = None
    ) -> Optional[Dict[str, Any]]:
        """Get X.509 certificate by ID or serial number."""
        with db_session() as db:
            query = db.x509_certificates

            if cert_id:
                query = query(db.x509_certificates.id == cert_id)
            elif serial_number:
                query = query(db.x509_certificates.serial_number == serial_number)
            else:
                return None

            cert = query.select().first()
            if cert:
                return self._cert_to_dict(cert)

        return None

    async def revoke_x509_certificate(
        self,
        cert_id: str = None,
        serial_number: str = None,
        reason: str = "unspecified",
        actor_id: Optional[str] = None,
    ) -> bool:
        """Revoke an X.509 certificate."""
        with db_session() as db:
            if cert_id:
                cert = db(db.x509_certificates.id == cert_id).select().first()
            elif serial_number:
                cert = (
                    db(db.x509_certificates.serial_number == serial_number)
                    .select()
                    .first()
                )
            else:
                return False

            if not cert:
                return False

            if cert.status == "revoked":
                return True  # Already revoked

            now = datetime.utcnow()
            db(db.x509_certificates.id == cert.id).update(
                status="revoked",
                revoked_at=now,
                revocation_reason=reason,
                updated_at=now,
            )

            # Add CRL entry
            db.crl_entries.insert(
                certificate_id=str(cert.id),
                serial_number=cert.serial_number,
                certificate_type="x509",
                revoked_at=now,
                revocation_reason=reason,
            )

            # Log audit
            self._log_audit(
                db=db,
                event_type="certificate_revoked",
                certificate_type="x509",
                certificate_id=str(cert.id),
                serial_number=cert.serial_number,
                subject=cert.subject,
                actor_id=actor_id,
                action="revoke",
                status="success",
                request_data={"reason": reason},
            )

            logger.info(
                "X.509 certificate revoked", serial=cert.serial_number, reason=reason
            )

        return True

    async def list_x509_certificates(
        self,
        status: Optional[str] = None,
        subject: Optional[str] = None,
        expires_before: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List X.509 certificates with filtering."""
        with db_session() as db:
            query = db.x509_certificates

            if status:
                query = query(db.x509_certificates.status == status)
            if subject:
                query = query(db.x509_certificates.subject.contains(subject))
            if expires_before:
                query = query(db.x509_certificates.not_after < expires_before)

            total = query.count()
            offset = (page - 1) * page_size

            certs = query.select(
                orderby=~db.x509_certificates.created_at,
                limitby=(offset, offset + page_size),
            )

            return [self._cert_to_dict(c, include_pem=False) for c in certs], total

    # =========================================================================
    # SSH Certificate Operations
    # =========================================================================
    async def issue_ssh_certificate(
        self,
        public_key: str,
        certificate_type: str = "user",
        key_id: str = None,
        principals: List[str] = None,
        validity_seconds: int = 86400,
        extensions: Dict[str, str] = None,
        critical_options: Dict[str, str] = None,
        source_addresses: List[str] = None,
        force_command: Optional[str] = None,
        hostname: Optional[str] = None,
        requester_id: Optional[str] = None,
        approval_request_id: Optional[str] = None,
        metadata: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Issue SSH certificate and store in database."""
        certificate, serial, cert_meta = await self.ssh_ca.issue_certificate(
            public_key=public_key,
            certificate_type=certificate_type,
            key_id=key_id,
            principals=principals,
            validity_seconds=validity_seconds,
            extensions=extensions,
            critical_options=critical_options,
            source_addresses=source_addresses,
            force_command=force_command,
            hostname=hostname,
        )

        # Store in database
        with db_session() as db:
            cert_id = str(uuid.uuid4())
            valid_after = datetime.fromisoformat(cert_meta["valid_after"])
            valid_before = datetime.fromisoformat(cert_meta["valid_before"])

            db.ssh_certificates.insert(
                id=cert_id,
                serial_number=serial,
                key_id=cert_meta["key_id"],
                certificate_type=certificate_type,
                principals=principals,
                valid_after=valid_after,
                valid_before=valid_before,
                key_type=cert_meta["key_type"],
                public_key=public_key,
                certificate=certificate,
                critical_options=critical_options or {},
                extensions=extensions or cert_meta.get("extensions", {}),
                source_address=source_addresses,
                force_command=force_command,
                status="active",
                hostname=hostname,
                requester_id=requester_id,
                approval_request_id=approval_request_id,
                metadata=metadata or {},
            )

            # Log audit
            self._log_audit(
                db=db,
                event_type="certificate_issued",
                certificate_type="ssh",
                certificate_id=cert_id,
                serial_number=serial,
                subject=cert_meta["key_id"],
                action="issue",
                status="success",
            )

        return {
            "id": cert_id,
            "serial_number": serial,
            "key_id": cert_meta["key_id"],
            "certificate_type": certificate_type,
            "principals": principals,
            "valid_after": valid_after,
            "valid_before": valid_before,
            "key_type": cert_meta["key_type"],
            "certificate": certificate,
            "ca_public_key": self.ssh_ca.get_ca_public_key(),
            "extensions": extensions or cert_meta.get("extensions", {}),
            "critical_options": critical_options or {},
            "status": "active",
            "created_at": datetime.utcnow(),
        }

    async def get_ssh_certificate(
        self, cert_id: str = None, serial_number: str = None
    ) -> Optional[Dict[str, Any]]:
        """Get SSH certificate by ID or serial number."""
        with db_session() as db:
            if cert_id:
                cert = db(db.ssh_certificates.id == cert_id).select().first()
            elif serial_number:
                cert = (
                    db(db.ssh_certificates.serial_number == serial_number)
                    .select()
                    .first()
                )
            else:
                return None

            if cert:
                return self._ssh_cert_to_dict(cert)

        return None

    async def revoke_ssh_certificate(
        self,
        cert_id: str = None,
        serial_number: str = None,
        reason: str = "unspecified",
        actor_id: Optional[str] = None,
    ) -> bool:
        """Revoke an SSH certificate."""
        with db_session() as db:
            if cert_id:
                cert = db(db.ssh_certificates.id == cert_id).select().first()
            elif serial_number:
                cert = (
                    db(db.ssh_certificates.serial_number == serial_number)
                    .select()
                    .first()
                )
            else:
                return False

            if not cert:
                return False

            if cert.status == "revoked":
                return True

            now = datetime.utcnow()
            db(db.ssh_certificates.id == cert.id).update(
                status="revoked",
                revoked_at=now,
                revocation_reason=reason,
                updated_at=now,
            )

            # Add CRL entry
            db.crl_entries.insert(
                certificate_id=str(cert.id),
                serial_number=cert.serial_number,
                certificate_type="ssh",
                revoked_at=now,
                revocation_reason=reason,
            )

            # Log audit
            self._log_audit(
                db=db,
                event_type="certificate_revoked",
                certificate_type="ssh",
                certificate_id=str(cert.id),
                serial_number=cert.serial_number,
                subject=cert.key_id,
                actor_id=actor_id,
                action="revoke",
                status="success",
                request_data={"reason": reason},
            )

            logger.info(
                "SSH certificate revoked", serial=cert.serial_number, reason=reason
            )

        return True

    async def list_ssh_certificates(
        self,
        status: Optional[str] = None,
        certificate_type: Optional[str] = None,
        principal: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List SSH certificates with filtering."""
        with db_session() as db:
            query = db.ssh_certificates

            if status:
                query = query(db.ssh_certificates.status == status)
            if certificate_type:
                query = query(db.ssh_certificates.certificate_type == certificate_type)
            if principal:
                query = query(db.ssh_certificates.principals.contains(principal))

            total = query.count()
            offset = (page - 1) * page_size

            certs = query.select(
                orderby=~db.ssh_certificates.created_at,
                limitby=(offset, offset + page_size),
            )

            return [self._ssh_cert_to_dict(c, include_cert=False) for c in certs], total

    # =========================================================================
    # CRL/KRL Operations
    # =========================================================================
    async def generate_x509_crl(self) -> Dict[str, Any]:
        """Generate X.509 CRL from revoked certificates."""
        with db_session() as db:
            entries = db(db.crl_entries.certificate_type == "x509").select()

            revoked = [
                {
                    "serial_number": e.serial_number,
                    "revoked_at": e.revoked_at,
                    "reason": e.revocation_reason,
                }
                for e in entries
            ]

        crl_pem, crl_number = await self.x509_ca.generate_crl(revoked)

        return {
            "crl_number": crl_number,
            "this_update": datetime.utcnow(),
            "next_update": datetime.utcnow() + timedelta(days=7),
            "revoked_certificates": revoked,
            "crl_pem": crl_pem,
        }

    async def generate_ssh_krl(self) -> Dict[str, Any]:
        """Generate SSH KRL from revoked certificates."""
        with db_session() as db:
            entries = db(db.crl_entries.certificate_type == "ssh").select()

            revoked = [{"serial_number": e.serial_number} for e in entries]

        krl_binary, krl_version = await self.ssh_ca.generate_krl(revoked)
        import base64

        return {
            "version": krl_version,
            "generated_at": datetime.utcnow(),
            "revoked_keys": revoked,
            "krl_binary": base64.b64encode(krl_binary).decode(),
        }

    # =========================================================================
    # Statistics
    # =========================================================================
    async def get_statistics(self) -> Dict[str, Any]:
        """Get certificate statistics."""
        with db_session() as db:
            now = datetime.utcnow()
            expiring_soon = now + timedelta(days=30)

            # X.509 stats
            x509_total = db(db.x509_certificates).count()
            x509_active = db(db.x509_certificates.status == "active").count()
            x509_revoked = db(db.x509_certificates.status == "revoked").count()
            x509_expired = db(db.x509_certificates.not_after < now).count()
            x509_expiring = db(
                (db.x509_certificates.status == "active")
                & (db.x509_certificates.not_after < expiring_soon)
                & (db.x509_certificates.not_after > now)
            ).count()

            # SSH stats
            ssh_total = db(db.ssh_certificates).count()
            ssh_active = db(db.ssh_certificates.status == "active").count()
            ssh_revoked = db(db.ssh_certificates.status == "revoked").count()

            return {
                "x509": {
                    "total": x509_total,
                    "active": x509_active,
                    "revoked": x509_revoked,
                    "expired": x509_expired,
                    "expiring_soon": x509_expiring,
                },
                "ssh": {
                    "total": ssh_total,
                    "active": ssh_active,
                    "revoked": ssh_revoked,
                },
                "timestamp": now.isoformat(),
            }

    # =========================================================================
    # Helper Methods
    # =========================================================================
    def _cert_to_dict(self, cert: Any, include_pem: bool = True) -> Dict[str, Any]:
        """Convert X.509 certificate row to dictionary."""
        result = {
            "id": str(cert.id),
            "serial_number": cert.serial_number,
            "subject": cert.subject,
            "issuer": cert.issuer,
            "not_before": cert.not_before,
            "not_after": cert.not_after,
            "key_algorithm": cert.key_algorithm,
            "key_size": cert.key_size,
            "fingerprint_sha256": cert.fingerprint_sha256,
            "san_dns": cert.san_dns or [],
            "san_ip": cert.san_ip or [],
            "san_email": cert.san_email or [],
            "status": cert.status,
            "revoked_at": cert.revoked_at,
            "revocation_reason": cert.revocation_reason,
            "created_at": cert.created_at,
        }

        if include_pem:
            result["certificate_pem"] = cert.certificate_pem
            result["private_key_pem"] = cert.private_key_pem

        return result

    def _ssh_cert_to_dict(self, cert: Any, include_cert: bool = True) -> Dict[str, Any]:
        """Convert SSH certificate row to dictionary."""
        result = {
            "id": str(cert.id),
            "serial_number": cert.serial_number,
            "key_id": cert.key_id,
            "certificate_type": cert.certificate_type,
            "principals": cert.principals or [],
            "valid_after": cert.valid_after,
            "valid_before": cert.valid_before,
            "key_type": cert.key_type,
            "hostname": cert.hostname,
            "status": cert.status,
            "revoked_at": cert.revoked_at,
            "revocation_reason": cert.revocation_reason,
            "extensions": cert.extensions or {},
            "critical_options": cert.critical_options or {},
            "created_at": cert.created_at,
        }

        if include_cert:
            result["certificate"] = cert.certificate
            result["public_key"] = cert.public_key

        return result

    def _log_audit(
        self,
        db: Any,
        event_type: str,
        certificate_type: str,
        certificate_id: str,
        serial_number: str,
        subject: str,
        action: str,
        status: str,
        actor_id: Optional[str] = None,
        actor_ip: Optional[str] = None,
        error_message: Optional[str] = None,
        request_data: Dict[str, Any] = None,
        response_data: Dict[str, Any] = None,
    ) -> None:
        """Log PKI audit event."""
        db.pki_audit_log.insert(
            event_type=event_type,
            certificate_type=certificate_type,
            certificate_id=certificate_id,
            serial_number=serial_number,
            subject=subject,
            actor_id=actor_id,
            actor_ip=actor_ip,
            action=action,
            status=status,
            error_message=error_message,
            request_data=request_data or {},
            response_data=response_data or {},
        )
