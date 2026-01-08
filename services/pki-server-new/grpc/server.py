"""gRPC server implementation for PKI Service."""
import asyncio
from concurrent import futures
from datetime import datetime
from typing import Optional

import grpc
from grpc import aio
import structlog

from ..config import Settings
from ..services.certificate_manager import CertificateManager

logger = structlog.get_logger()

# Import generated protobuf modules (will be generated at build time)
try:
    from .generated import pki_pb2, pki_pb2_grpc
except ImportError:
    logger.warning("gRPC stubs not yet generated, server will not start")
    pki_pb2 = None
    pki_pb2_grpc = None


# Enum mapping helpers
KEY_ALG_MAP = {
    "RSA": 1,
    "ECDSA": 2,
    "ED25519": 3,
}

KEY_ALG_REVERSE = {v: k for k, v in KEY_ALG_MAP.items()}

STATUS_MAP = {
    "active": 1,
    "revoked": 2,
    "expired": 3,
    "pending": 4,
}

STATUS_REVERSE = {v: k for k, v in STATUS_MAP.items()}

REVOCATION_MAP = {
    "unspecified": 0,
    "key_compromise": 1,
    "ca_compromise": 2,
    "affiliation_changed": 3,
    "superseded": 4,
    "cessation_of_operation": 5,
    "certificate_hold": 6,
    "privilege_withdrawn": 7,
}

REVOCATION_REVERSE = {v: k for k, v in REVOCATION_MAP.items()}

SSH_CERT_TYPE_MAP = {
    "user": 1,
    "host": 2,
}

SSH_CERT_TYPE_REVERSE = {v: k for k, v in SSH_CERT_TYPE_MAP.items()}


class PKIServiceServicer:
    """gRPC servicer for PKI operations."""

    def __init__(self, cert_manager: CertificateManager, config: Settings):
        """Initialize PKI servicer."""
        self.cert_manager = cert_manager
        self.config = config

    # =========================================================================
    # X.509 Certificate Operations
    # =========================================================================
    async def IssueX509Certificate(self, request, context):
        """Issue a new X.509 certificate."""
        try:
            # Map key algorithm
            key_alg = KEY_ALG_REVERSE.get(request.key_algorithm, "RSA")

            # Map key usage
            key_usage = []
            ku_map = {
                1: "digital_signature",
                2: "key_encipherment",
                3: "data_encipherment",
                4: "key_agreement",
                5: "key_cert_sign",
                6: "crl_sign",
            }
            for ku in request.key_usage:
                if ku in ku_map:
                    key_usage.append(ku_map[ku])

            # Map extended key usage
            eku = []
            eku_map = {
                1: "server_auth",
                2: "client_auth",
                3: "code_signing",
                4: "email_protection",
                5: "time_stamping",
                6: "ocsp_signing",
            }
            for e in request.extended_key_usage:
                if e in eku_map:
                    eku.append(eku_map[e])

            result = await self.cert_manager.issue_x509_certificate(
                subject=request.subject,
                key_algorithm=key_alg,
                key_size=request.key_size or 4096,
                validity_days=request.validity_days or 365,
                san_dns=list(request.san_dns),
                san_ip=list(request.san_ip),
                san_email=list(request.san_email),
                key_usage=key_usage or ["digital_signature", "key_encipherment"],
                extended_key_usage=eku or ["server_auth"],
                is_ca=request.is_ca,
                path_length=request.path_length if request.is_ca else None,
                csr_pem=request.csr_pem or None,
                requester_id=request.requester_id or None,
                approval_request_id=request.approval_request_id or None,
            )

            return pki_pb2.X509CertResponse(
                id=result["id"],
                serial_number=result["serial_number"],
                subject=result["subject"],
                issuer=result["issuer"],
                not_before=result["not_before"].isoformat(),
                not_after=result["not_after"].isoformat(),
                key_algorithm=KEY_ALG_MAP.get(key_alg, 0),
                key_size=result.get("key_size") or 0,
                fingerprint_sha256=result["fingerprint_sha256"],
                certificate_pem=result["certificate_pem"],
                private_key_pem=result.get("private_key_pem") or "",
                san_dns=result.get("san_dns", []),
                san_ip=result.get("san_ip", []),
                status=STATUS_MAP.get(result["status"], 0),
                created_at=result["created_at"].isoformat(),
            )

        except Exception as e:
            logger.error("gRPC IssueX509Certificate failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.X509CertResponse()

    async def GetX509Certificate(self, request, context):
        """Get X.509 certificate by ID or serial."""
        try:
            cert_id = request.id if request.HasField("id") else None
            serial = request.serial_number if request.HasField("serial_number") else None

            cert = await self.cert_manager.get_x509_certificate(
                cert_id=cert_id, serial_number=serial
            )

            if not cert:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Certificate not found")
                return pki_pb2.X509CertResponse()

            return pki_pb2.X509CertResponse(
                id=cert["id"],
                serial_number=cert["serial_number"],
                subject=cert["subject"],
                issuer=cert["issuer"],
                not_before=cert["not_before"].isoformat(),
                not_after=cert["not_after"].isoformat(),
                fingerprint_sha256=cert["fingerprint_sha256"],
                certificate_pem=cert.get("certificate_pem", ""),
                san_dns=cert.get("san_dns", []),
                san_ip=cert.get("san_ip", []),
                status=STATUS_MAP.get(cert["status"], 0),
                created_at=cert["created_at"].isoformat(),
            )

        except Exception as e:
            logger.error("gRPC GetX509Certificate failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.X509CertResponse()

    async def RevokeX509Certificate(self, request, context):
        """Revoke an X.509 certificate."""
        try:
            cert_id = request.id if request.HasField("id") else None
            serial = request.serial_number if request.HasField("serial_number") else None
            reason = REVOCATION_REVERSE.get(request.reason, "unspecified")

            success = await self.cert_manager.revoke_x509_certificate(
                cert_id=cert_id,
                serial_number=serial,
                reason=reason,
            )

            if not success:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Certificate not found")
                return pki_pb2.RevokeResponse(success=False)

            return pki_pb2.RevokeResponse(
                success=True,
                message="Certificate revoked",
                serial_number=serial or "",
                revoked_at=datetime.utcnow().isoformat(),
            )

        except Exception as e:
            logger.error("gRPC RevokeX509Certificate failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.RevokeResponse(success=False, message=str(e))

    async def GetX509Status(self, request, context):
        """Get X.509 certificate status."""
        try:
            cert_id = request.id if request.HasField("id") else None
            serial = request.serial_number if request.HasField("serial_number") else None

            cert = await self.cert_manager.get_x509_certificate(
                cert_id=cert_id, serial_number=serial
            )

            if not cert:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Certificate not found")
                return pki_pb2.StatusResponse()

            now = datetime.utcnow()
            is_expired = cert["not_after"] < now

            return pki_pb2.StatusResponse(
                id=cert["id"],
                serial_number=cert["serial_number"],
                status=STATUS_MAP.get(cert["status"], 0),
                is_expired=is_expired,
                not_before=cert["not_before"].isoformat(),
                not_after=cert["not_after"].isoformat(),
                revoked_at=cert["revoked_at"].isoformat() if cert.get("revoked_at") else "",
                revocation_reason=cert.get("revocation_reason") or "",
            )

        except Exception as e:
            logger.error("gRPC GetX509Status failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.StatusResponse()

    async def ListX509Certificates(self, request, context):
        """List X.509 certificates."""
        try:
            status = STATUS_REVERSE.get(request.status) if request.status else None

            certs, total = await self.cert_manager.list_x509_certificates(
                status=status,
                subject=request.subject or None,
                page=request.page or 1,
                page_size=request.page_size or 50,
            )

            cert_infos = [
                pki_pb2.X509CertInfo(
                    id=c["id"],
                    serial_number=c["serial_number"],
                    subject=c["subject"],
                    issuer=c["issuer"],
                    not_before=c["not_before"].isoformat(),
                    not_after=c["not_after"].isoformat(),
                    fingerprint_sha256=c["fingerprint_sha256"],
                    status=STATUS_MAP.get(c["status"], 0),
                    revoked_at=c["revoked_at"].isoformat() if c.get("revoked_at") else "",
                    created_at=c["created_at"].isoformat(),
                )
                for c in certs
            ]

            page = request.page or 1
            page_size = request.page_size or 50

            return pki_pb2.X509CertListResponse(
                certificates=cert_infos,
                total=total,
                page=page,
                page_size=page_size,
                pages=(total + page_size - 1) // page_size,
            )

        except Exception as e:
            logger.error("gRPC ListX509Certificates failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.X509CertListResponse()

    # =========================================================================
    # SSH Certificate Operations
    # =========================================================================
    async def IssueSSHCertificate(self, request, context):
        """Issue a new SSH certificate."""
        try:
            cert_type = SSH_CERT_TYPE_REVERSE.get(request.certificate_type, "user")

            result = await self.cert_manager.issue_ssh_certificate(
                public_key=request.public_key,
                certificate_type=cert_type,
                key_id=request.key_id,
                principals=list(request.principals),
                validity_seconds=request.validity_seconds or 86400,
                extensions=dict(request.extensions),
                critical_options=dict(request.critical_options),
                source_addresses=list(request.source_addresses),
                force_command=request.force_command or None,
                hostname=request.hostname or None,
                requester_id=request.requester_id or None,
                approval_request_id=request.approval_request_id or None,
            )

            return pki_pb2.SSHCertResponse(
                id=result["id"],
                serial_number=result["serial_number"],
                key_id=result["key_id"],
                certificate_type=SSH_CERT_TYPE_MAP.get(cert_type, 0),
                principals=result["principals"],
                valid_after=result["valid_after"].isoformat(),
                valid_before=result["valid_before"].isoformat(),
                key_type=result["key_type"],
                certificate=result["certificate"],
                ca_public_key=result["ca_public_key"],
                extensions=result.get("extensions", {}),
                critical_options=result.get("critical_options", {}),
                status=STATUS_MAP.get(result["status"], 0),
                created_at=result["created_at"].isoformat(),
            )

        except Exception as e:
            logger.error("gRPC IssueSSHCertificate failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.SSHCertResponse()

    async def GetSSHCertificate(self, request, context):
        """Get SSH certificate by ID or serial."""
        try:
            cert_id = request.id if request.HasField("id") else None
            serial = request.serial_number if request.HasField("serial_number") else None

            cert = await self.cert_manager.get_ssh_certificate(
                cert_id=cert_id, serial_number=serial
            )

            if not cert:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Certificate not found")
                return pki_pb2.SSHCertResponse()

            return pki_pb2.SSHCertResponse(
                id=cert["id"],
                serial_number=cert["serial_number"],
                key_id=cert["key_id"],
                certificate_type=SSH_CERT_TYPE_MAP.get(cert["certificate_type"], 0),
                principals=cert["principals"],
                valid_after=cert["valid_after"].isoformat(),
                valid_before=cert["valid_before"].isoformat(),
                key_type=cert["key_type"],
                certificate=cert.get("certificate", ""),
                ca_public_key=self.cert_manager.ssh_ca.get_ca_public_key(),
                extensions=cert.get("extensions", {}),
                critical_options=cert.get("critical_options", {}),
                status=STATUS_MAP.get(cert["status"], 0),
                created_at=cert["created_at"].isoformat(),
            )

        except Exception as e:
            logger.error("gRPC GetSSHCertificate failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.SSHCertResponse()

    async def RevokeSSHCertificate(self, request, context):
        """Revoke an SSH certificate."""
        try:
            cert_id = request.id if request.HasField("id") else None
            serial = request.serial_number if request.HasField("serial_number") else None
            reason = REVOCATION_REVERSE.get(request.reason, "unspecified")

            success = await self.cert_manager.revoke_ssh_certificate(
                cert_id=cert_id,
                serial_number=serial,
                reason=reason,
            )

            if not success:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Certificate not found")
                return pki_pb2.RevokeResponse(success=False)

            return pki_pb2.RevokeResponse(
                success=True,
                message="Certificate revoked",
                serial_number=serial or "",
                revoked_at=datetime.utcnow().isoformat(),
            )

        except Exception as e:
            logger.error("gRPC RevokeSSHCertificate failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.RevokeResponse(success=False, message=str(e))

    async def GetSSHStatus(self, request, context):
        """Get SSH certificate status."""
        try:
            cert_id = request.id if request.HasField("id") else None
            serial = request.serial_number if request.HasField("serial_number") else None

            cert = await self.cert_manager.get_ssh_certificate(
                cert_id=cert_id, serial_number=serial
            )

            if not cert:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Certificate not found")
                return pki_pb2.StatusResponse()

            now = datetime.utcnow()
            is_expired = cert["valid_before"] < now

            return pki_pb2.StatusResponse(
                id=cert["id"],
                serial_number=cert["serial_number"],
                status=STATUS_MAP.get(cert["status"], 0),
                is_expired=is_expired,
                not_before=cert["valid_after"].isoformat(),
                not_after=cert["valid_before"].isoformat(),
                revoked_at=cert["revoked_at"].isoformat() if cert.get("revoked_at") else "",
                revocation_reason=cert.get("revocation_reason") or "",
            )

        except Exception as e:
            logger.error("gRPC GetSSHStatus failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.StatusResponse()

    async def ListSSHCertificates(self, request, context):
        """List SSH certificates."""
        try:
            status = STATUS_REVERSE.get(request.status) if request.status else None
            cert_type = SSH_CERT_TYPE_REVERSE.get(request.certificate_type) if hasattr(request, 'certificate_type') else None

            certs, total = await self.cert_manager.list_ssh_certificates(
                status=status,
                certificate_type=cert_type,
                principal=request.principal or None,
                page=request.page or 1,
                page_size=request.page_size or 50,
            )

            cert_infos = [
                pki_pb2.SSHCertInfo(
                    id=c["id"],
                    serial_number=c["serial_number"],
                    key_id=c["key_id"],
                    certificate_type=SSH_CERT_TYPE_MAP.get(c["certificate_type"], 0),
                    principals=c["principals"],
                    valid_after=c["valid_after"].isoformat(),
                    valid_before=c["valid_before"].isoformat(),
                    key_type=c["key_type"],
                    hostname=c.get("hostname") or "",
                    status=STATUS_MAP.get(c["status"], 0),
                    revoked_at=c["revoked_at"].isoformat() if c.get("revoked_at") else "",
                    created_at=c["created_at"].isoformat(),
                )
                for c in certs
            ]

            page = request.page or 1
            page_size = request.page_size or 50

            return pki_pb2.SSHCertListResponse(
                certificates=cert_infos,
                total=total,
                page=page,
                page_size=page_size,
                pages=(total + page_size - 1) // page_size,
            )

        except Exception as e:
            logger.error("gRPC ListSSHCertificates failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.SSHCertListResponse()

    # =========================================================================
    # CRL/KRL Operations
    # =========================================================================
    async def GetCRL(self, request, context):
        """Get Certificate Revocation List."""
        try:
            crl = await self.cert_manager.generate_x509_crl()

            entries = [
                pki_pb2.RevokedCertEntry(
                    serial_number=e["serial_number"],
                    revoked_at=e["revoked_at"].isoformat() if isinstance(e["revoked_at"], datetime) else e["revoked_at"],
                    reason=e.get("reason", "unspecified"),
                )
                for e in crl["revoked_certificates"]
            ]

            return pki_pb2.CRLResponse(
                crl_number=crl["crl_number"],
                this_update=crl["this_update"].isoformat(),
                next_update=crl["next_update"].isoformat(),
                revoked_certificates=entries,
                crl_pem=crl["crl_pem"],
            )

        except Exception as e:
            logger.error("gRPC GetCRL failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.CRLResponse()

    async def GetKRL(self, request, context):
        """Get Key Revocation List."""
        try:
            import base64
            krl = await self.cert_manager.generate_ssh_krl()

            entries = [
                pki_pb2.RevokedCertEntry(serial_number=e["serial_number"])
                for e in krl["revoked_keys"]
            ]

            return pki_pb2.KRLResponse(
                version=krl["version"],
                generated_at=krl["generated_at"].isoformat(),
                revoked_keys=entries,
                krl_binary=base64.b64decode(krl["krl_binary"]),
            )

        except Exception as e:
            logger.error("gRPC GetKRL failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.KRLResponse()

    # =========================================================================
    # CA Information
    # =========================================================================
    async def GetX509CAInfo(self, request, context):
        """Get X.509 CA information."""
        try:
            info = self.cert_manager.x509_ca.get_ca_info()
            ca_pem = self.cert_manager.x509_ca.get_ca_certificate_pem()

            return pki_pb2.X509CAInfoResponse(
                subject=info["subject"],
                issuer=info["issuer"],
                not_before=info["not_before"],
                not_after=info["not_after"],
                fingerprint_sha256=info["fingerprint_sha256"],
                serial_counter=info["serial_counter"],
                crl_number=info["crl_number"],
                ca_certificate_pem=ca_pem,
            )

        except Exception as e:
            logger.error("gRPC GetX509CAInfo failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.X509CAInfoResponse()

    async def GetSSHCAInfo(self, request, context):
        """Get SSH CA information."""
        try:
            info = self.cert_manager.ssh_ca.get_ca_info()

            return pki_pb2.SSHCAInfoResponse(
                ca_public_key=info["ca_public_key"],
                key_type=info["key_type"],
                fingerprint=info["fingerprint"],
                serial_counter=info["serial_counter"],
                krl_version=info["krl_version"],
            )

        except Exception as e:
            logger.error("gRPC GetSSHCAInfo failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.SSHCAInfoResponse()

    # =========================================================================
    # Health and Statistics
    # =========================================================================
    async def HealthCheck(self, request, context):
        """Health check endpoint."""
        return pki_pb2.HealthResponse(
            healthy=True,
            version=self.config.version,
            timestamp=datetime.utcnow().isoformat(),
            components={
                "x509_ca": True,
                "ssh_ca": True,
                "database": True,
            },
        )

    async def GetStatistics(self, request, context):
        """Get PKI statistics."""
        try:
            stats = await self.cert_manager.get_statistics()

            return pki_pb2.StatisticsResponse(
                x509=pki_pb2.X509Statistics(
                    total=stats["x509"]["total"],
                    active=stats["x509"]["active"],
                    revoked=stats["x509"]["revoked"],
                    expired=stats["x509"]["expired"],
                    expiring_soon=stats["x509"]["expiring_soon"],
                ),
                ssh=pki_pb2.SSHStatistics(
                    total=stats["ssh"]["total"],
                    active=stats["ssh"]["active"],
                    revoked=stats["ssh"]["revoked"],
                ),
                timestamp=stats["timestamp"],
            )

        except Exception as e:
            logger.error("gRPC GetStatistics failed", error=str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return pki_pb2.StatisticsResponse()


async def serve_grpc(
    cert_manager: CertificateManager,
    config: Settings,
    port: int = 50052,
) -> aio.Server:
    """Start the gRPC server."""
    if pki_pb2_grpc is None:
        logger.error("gRPC stubs not generated, cannot start server")
        return None

    server = aio.server(
        futures.ThreadPoolExecutor(max_workers=config.grpc.max_workers),
        options=[
            ("grpc.max_receive_message_length", config.grpc.max_message_length),
            ("grpc.max_send_message_length", config.grpc.max_message_length),
        ],
    )

    servicer = PKIServiceServicer(cert_manager, config)
    pki_pb2_grpc.add_PKIServiceServicer_to_server(servicer, server)

    server.add_insecure_port(f"[::]:{port}")
    await server.start()

    logger.info("gRPC server started", port=port)
    return server
