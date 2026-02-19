"""
Async SSH Certificate Processing for SkausWatch SSH CA

Provides high-performance async SSH certificate operations including signing,
revocation, KRL management, and SSH configuration generation with caching.
"""

import asyncio
import logging
import time
import base64
import struct
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import uuid4
import json

# SSH key handling
import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519

from ...shared.performance import (
    AsyncTaskManager,
    async_retry,
    async_timeout,
    async_batch_processor,
    ThreadPoolManager,
    TaskType,
    CPUBoundTaskManager,
    IOBoundTaskManager,
    CacheManager,
    CacheConfig,
    cache_decorator,
    RateLimiter,
    RateLimitConfig,
    RateLimitStrategy,
)

logger = logging.getLogger(__name__)


class SSHCertificateType(Enum):
    """SSH certificate types"""

    USER = "user"
    HOST = "host"


class SSHCertificateStatus(Enum):
    """SSH certificate status"""

    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class SSHCertificateRequest:
    """SSH certificate signing request"""

    request_id: str
    certificate_type: SSHCertificateType
    public_key: str  # SSH public key
    principals: List[str]  # User names or hostnames
    validity_duration: int = 3600  # Seconds
    extensions: Dict[str, str] = field(default_factory=dict)
    critical_options: Dict[str, str] = field(default_factory=dict)
    source_address: Optional[str] = None
    force_command: Optional[str] = None
    requester_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SSHCertificateResponse:
    """SSH certificate response"""

    certificate_id: str
    certificate_type: SSHCertificateType
    signed_certificate: str  # SSH certificate
    serial_number: int
    principals: List[str]
    valid_after: datetime
    valid_before: datetime
    public_key_fingerprint: str
    ca_fingerprint: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KRLEntry:
    """Key Revocation List entry"""

    serial_number: int
    revocation_time: datetime
    reason: str
    certificate_fingerprint: Optional[str] = None


@dataclass
class SSHProcessingMetrics:
    """SSH processing metrics"""

    certificates_signed: int = 0
    certificates_revoked: int = 0
    krl_updates: int = 0
    config_generations: int = 0
    average_signing_time: float = 0.0
    queue_size: int = 0
    cache_hit_rate: float = 0.0
    error_count: int = 0


class AsyncSSHProcessor:
    """High-performance async SSH certificate processor"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metrics = SSHProcessingMetrics()

        # CA keys
        self.ca_private_key: Optional[paramiko.RSAKey] = None
        self.ca_public_key: Optional[str] = None
        self.ca_fingerprint: Optional[str] = None

        # Initialize managers
        self.task_manager = AsyncTaskManager()
        self.thread_pool_manager = ThreadPoolManager()
        self.cache_manager = CacheManager()

        # Certificate storage
        self.certificates: Dict[str, Dict[str, Any]] = {}
        self.revoked_certificates: Dict[int, KRLEntry] = {}  # serial -> KRL entry
        self.serial_counter = 1000000  # Start with high number

        # Processing queues
        self.signing_queue = asyncio.Queue(maxsize=2000)
        self.revocation_queue = asyncio.Queue(maxsize=500)
        self.krl_queue = asyncio.Queue(maxsize=100)
        self.config_queue = asyncio.Queue(maxsize=1000)

        # Rate limiters
        self.rate_limiters = {}

        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.running = False

    async def initialize(self):
        """Initialize the SSH processor"""
        # Start managers
        await self.task_manager.start()

        # Create specialized thread pools
        self.cpu_manager = CPUBoundTaskManager(self.thread_pool_manager)
        self.io_manager = IOBoundTaskManager(self.thread_pool_manager)

        # Initialize caching
        cache_configs = {
            "certificates": CacheConfig(
                max_size=20000,
                default_ttl=3600.0,
                eviction_policy="lru",
                metrics_enabled=True,
            ),
            "public_keys": CacheConfig(
                max_size=50000, default_ttl=1800.0, eviction_policy="lru"  # 30 minutes
            ),
            "ssh_configs": CacheConfig(
                max_size=10000, default_ttl=600.0, eviction_policy="lru"  # 10 minutes
            ),
            "krl": CacheConfig(
                max_size=1000, default_ttl=3600.0, eviction_policy="lru"
            ),
        }

        for name, config in cache_configs.items():
            self.cache_manager.create_memory_cache(name, config)

        # Load CA keys
        await self._load_ca_keys()

        # Set up rate limiting
        self._setup_rate_limiters()

        # Load existing data
        await self._load_existing_data()

        self.running = True

        # Start background processors
        await self._start_background_processors()

        logger.info("Async SSH processor initialized")

    async def shutdown(self):
        """Shutdown the processor"""
        self.running = False

        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()

        await asyncio.gather(*self.background_tasks, return_exceptions=True)

        # Shutdown managers
        await self.task_manager.stop()
        await self.thread_pool_manager.shutdown_all()
        await self.cache_manager.close_all()

        logger.info("SSH processor shutdown complete")

    async def _load_ca_keys(self):
        """Load CA private and public keys"""
        try:
            # Load from config or generate new keys
            ca_key_path = self.config.get("ca_private_key_path")

            if ca_key_path:
                # Load existing CA key
                with open(ca_key_path, "r") as f:
                    self.ca_private_key = paramiko.RSAKey.from_private_key_file(
                        ca_key_path
                    )
            else:
                # Generate new CA key for demo
                self.ca_private_key = paramiko.RSAKey.generate(2048)

            # Get public key
            self.ca_public_key = f"ssh-rsa {self.ca_private_key.get_base64()}"

            # Calculate fingerprint
            public_key_bytes = base64.b64decode(self.ca_private_key.get_base64())
            import hashlib

            self.ca_fingerprint = hashlib.sha256(public_key_bytes).hexdigest()

            logger.info(f"CA keys loaded, fingerprint: {self.ca_fingerprint[:16]}...")

        except Exception as e:
            logger.error(f"Failed to load CA keys: {e}")
            raise

    def _setup_rate_limiters(self):
        """Setup rate limiters"""
        self.rate_limiters["certificate_signing"] = RateLimiter(
            RateLimitConfig(
                strategy=RateLimitStrategy.TOKEN_BUCKET,
                requests=200,  # 200 certificates per minute
                window_seconds=60.0,
                burst_size=50,
            )
        )

        self.rate_limiters["revocation"] = RateLimiter(
            RateLimitConfig(
                strategy=RateLimitStrategy.SLIDING_WINDOW,
                requests=100,  # 100 revocations per minute
                window_seconds=60.0,
            )
        )

        self.rate_limiters["config_generation"] = RateLimiter(
            RateLimitConfig(
                strategy=RateLimitStrategy.FIXED_WINDOW,
                requests=500,  # 500 configs per minute
                window_seconds=60.0,
            )
        )

    async def _load_existing_data(self):
        """Load existing certificates and revocations"""
        # In production, this would load from database
        logger.info("SSH certificate storage initialized")

    async def _start_background_processors(self):
        """Start background processing tasks"""
        # SSH certificate signing workers
        for i in range(4):  # 4 signing workers
            task = asyncio.create_task(
                self._signing_processor_worker(f"ssh-signer-{i}")
            )
            self.background_tasks.append(task)

        # Revocation processor
        task = asyncio.create_task(self._revocation_processor_worker())
        self.background_tasks.append(task)

        # KRL generation worker
        task = asyncio.create_task(self._krl_processor_worker())
        self.background_tasks.append(task)

        # SSH config generation workers
        for i in range(2):
            task = asyncio.create_task(
                self._config_processor_worker(f"config-worker-{i}")
            )
            self.background_tasks.append(task)

        # Maintenance worker
        task = asyncio.create_task(self._maintenance_worker())
        self.background_tasks.append(task)

        logger.info(f"Started {len(self.background_tasks)} SSH background workers")

    @async_retry(max_attempts=3, delay=1.0)
    async def submit_signing_request(self, request: SSHCertificateRequest) -> str:
        """Submit SSH certificate signing request"""
        # Check rate limit
        if not await self.rate_limiters["certificate_signing"].is_allowed(
            request.requester_id
        ):
            raise Exception("Certificate signing rate limit exceeded")

        # Add to processing queue
        await self.signing_queue.put(request)

        self.metrics.queue_size = self.signing_queue.qsize()

        logger.info(f"SSH certificate request {request.request_id} queued")
        return request.request_id

    async def submit_revocation_request(
        self, certificate_id: str, serial_number: int, reason: str, revoked_by: str
    ) -> bool:
        """Submit SSH certificate revocation request"""
        if not await self.rate_limiters["revocation"].is_allowed(revoked_by):
            raise Exception("Revocation rate limit exceeded")

        revocation_data = {
            "certificate_id": certificate_id,
            "serial_number": serial_number,
            "reason": reason,
            "revoked_by": revoked_by,
            "revocation_time": datetime.utcnow(),
        }

        await self.revocation_queue.put(revocation_data)
        return True

    async def submit_config_request(
        self, config_type: str, user_id: str, parameters: Dict[str, Any]
    ) -> str:
        """Submit SSH config generation request"""
        if not await self.rate_limiters["config_generation"].is_allowed(user_id):
            raise Exception("Config generation rate limit exceeded")

        request_id = str(uuid4())
        config_request = {
            "request_id": request_id,
            "config_type": config_type,
            "user_id": user_id,
            "parameters": parameters,
            "submitted_at": datetime.utcnow(),
        }

        await self.config_queue.put(config_request)
        return request_id

    @cache_decorator(cache_name="certificates", ttl=3600.0)
    async def get_certificate(self, certificate_id: str) -> Optional[Dict[str, Any]]:
        """Get SSH certificate by ID with caching"""
        return self.certificates.get(certificate_id)

    async def _signing_processor_worker(self, worker_name: str):
        """Worker for processing SSH certificate signing requests"""
        logger.info(f"SSH signing worker {worker_name} started")

        while self.running:
            try:
                request = await asyncio.wait_for(self.signing_queue.get(), timeout=1.0)

                await self._process_signing_request(request, worker_name)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"SSH signing worker {worker_name} error: {e}")
                self.metrics.error_count += 1

        logger.info(f"SSH signing worker {worker_name} stopped")

    async def _process_signing_request(
        self, request: SSHCertificateRequest, worker_name: str
    ):
        """Process SSH certificate signing request"""
        start_time = time.time()

        try:
            # Sign certificate in thread pool (CPU-bound)
            certificate_data = await self._sign_certificate_async(request)

            # Store certificate
            self.certificates[request.request_id] = {
                **certificate_data,
                "processed_by": worker_name,
                "processed_at": datetime.utcnow().isoformat(),
            }

            # Update metrics
            processing_time = time.time() - start_time
            self.metrics.certificates_signed += 1

            if self.metrics.average_signing_time == 0:
                self.metrics.average_signing_time = processing_time
            else:
                self.metrics.average_signing_time = (
                    self.metrics.average_signing_time * 0.9 + processing_time * 0.1
                )

            # Invalidate cache
            cache = self.cache_manager.get_cache("certificates")
            if cache:
                await cache.delete(request.request_id)

            logger.info(
                f"SSH certificate {request.request_id} signed by {worker_name} "
                f"in {processing_time:.2f}s"
            )

        except Exception as e:
            logger.error(
                f"Failed to process SSH signing request {request.request_id}: {e}"
            )
            self.metrics.error_count += 1
            raise

    @async_timeout(30.0)
    async def _sign_certificate_async(
        self, request: SSHCertificateRequest
    ) -> Dict[str, Any]:
        """Sign SSH certificate asynchronously"""
        return await self.cpu_manager.submit_computation(
            self._sign_certificate_sync, request
        )

    def _sign_certificate_sync(self, request: SSHCertificateRequest) -> Dict[str, Any]:
        """Sign SSH certificate synchronously (CPU-bound)"""
        # Parse public key
        try:
            key_parts = request.public_key.strip().split()
            if len(key_parts) < 2:
                raise ValueError("Invalid public key format")

            key_type = key_parts[0]
            key_data = base64.b64decode(key_parts[1])

            # Create SSH certificate
            serial_number = self._get_next_serial()

            # Calculate validity period
            valid_after = int(time.time())
            valid_before = valid_after + request.validity_duration

            # Build certificate
            cert_data = self._build_ssh_certificate(
                key_type=key_type,
                public_key_data=key_data,
                serial_number=serial_number,
                cert_type=(
                    1 if request.certificate_type == SSHCertificateType.USER else 2
                ),
                key_id=f"{request.certificate_type.value}-{request.request_id}",
                valid_principals=request.principals,
                valid_after=valid_after,
                valid_before=valid_before,
                critical_options=request.critical_options,
                extensions=request.extensions,
            )

            # Sign with CA key
            signed_cert = self._sign_certificate_data(cert_data)

            # Calculate fingerprint
            public_key_fingerprint = self._calculate_key_fingerprint(key_data)

            return {
                "certificate_id": request.request_id,
                "certificate_type": request.certificate_type.value,
                "signed_certificate": signed_cert,
                "serial_number": serial_number,
                "principals": request.principals,
                "valid_after": datetime.fromtimestamp(valid_after),
                "valid_before": datetime.fromtimestamp(valid_before),
                "public_key_fingerprint": public_key_fingerprint,
                "ca_fingerprint": self.ca_fingerprint,
                "metadata": request.metadata,
            }

        except Exception as e:
            logger.error(f"SSH certificate signing failed: {e}")
            raise

    def _get_next_serial(self) -> int:
        """Get next serial number"""
        self.serial_counter += 1
        return self.serial_counter

    def _build_ssh_certificate(
        self,
        key_type: str,
        public_key_data: bytes,
        serial_number: int,
        cert_type: int,
        key_id: str,
        valid_principals: List[str],
        valid_after: int,
        valid_before: int,
        critical_options: Dict[str, str],
        extensions: Dict[str, str],
    ) -> bytes:
        """Build SSH certificate data structure"""
        # This is a simplified SSH certificate builder
        # In production, you'd use a proper SSH certificate library

        # SSH certificate format (simplified):
        # - nonce (random bytes)
        # - public key
        # - serial
        # - type
        # - key id
        # - valid principals
        # - valid after
        # - valid before
        # - critical options
        # - extensions
        # - reserved
        # - signature key

        import struct
        import os

        cert_data = b""

        # Add nonce (32 random bytes)
        nonce = os.urandom(32)
        cert_data += struct.pack(">I", len(nonce)) + nonce

        # Add public key blob
        cert_data += struct.pack(">I", len(public_key_data)) + public_key_data

        # Add serial number
        cert_data += struct.pack(">Q", serial_number)

        # Add certificate type
        cert_data += struct.pack(">I", cert_type)

        # Add key ID
        key_id_bytes = key_id.encode("utf-8")
        cert_data += struct.pack(">I", len(key_id_bytes)) + key_id_bytes

        # Add valid principals
        principals_data = b""
        for principal in valid_principals:
            principal_bytes = principal.encode("utf-8")
            principals_data += struct.pack(">I", len(principal_bytes)) + principal_bytes
        cert_data += struct.pack(">I", len(principals_data)) + principals_data

        # Add validity period
        cert_data += struct.pack(">Q", valid_after)
        cert_data += struct.pack(">Q", valid_before)

        # Add critical options (simplified)
        options_data = b""
        for key, value in critical_options.items():
            key_bytes = key.encode("utf-8")
            value_bytes = value.encode("utf-8")
            options_data += struct.pack(">I", len(key_bytes)) + key_bytes
            options_data += struct.pack(">I", len(value_bytes)) + value_bytes
        cert_data += struct.pack(">I", len(options_data)) + options_data

        # Add extensions (simplified)
        ext_data = b""
        for key, value in extensions.items():
            key_bytes = key.encode("utf-8")
            value_bytes = value.encode("utf-8")
            ext_data += struct.pack(">I", len(key_bytes)) + key_bytes
            ext_data += struct.pack(">I", len(value_bytes)) + value_bytes
        cert_data += struct.pack(">I", len(ext_data)) + ext_data

        # Add reserved field
        cert_data += struct.pack(">I", 0)

        # Add CA public key
        ca_key_bytes = base64.b64decode(self.ca_private_key.get_base64())
        cert_data += struct.pack(">I", len(ca_key_bytes)) + ca_key_bytes

        return cert_data

    def _sign_certificate_data(self, cert_data: bytes) -> str:
        """Sign certificate data with CA private key"""
        # Sign the certificate data
        signature = self.ca_private_key.sign_ssh_data(cert_data)

        # Build final certificate
        cert_type = "ssh-rsa-cert-v01@openssh.com"  # Simplified
        cert_blob = cert_data + signature

        # Encode as SSH certificate format
        cert_b64 = base64.b64encode(cert_blob).decode("ascii")

        return f"{cert_type} {cert_b64}"

    def _calculate_key_fingerprint(self, key_data: bytes) -> str:
        """Calculate SSH key fingerprint"""
        import hashlib

        return hashlib.sha256(key_data).hexdigest()

    async def _revocation_processor_worker(self):
        """Worker for processing revocation requests"""
        logger.info("SSH revocation processor started")

        while self.running:
            try:
                revocation_data = await asyncio.wait_for(
                    self.revocation_queue.get(), timeout=1.0
                )

                await self._process_revocation(revocation_data)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"SSH revocation processor error: {e}")
                self.metrics.error_count += 1

        logger.info("SSH revocation processor stopped")

    async def _process_revocation(self, revocation_data: Dict[str, Any]):
        """Process SSH certificate revocation"""
        certificate_id = revocation_data["certificate_id"]
        serial_number = revocation_data["serial_number"]

        # Check if certificate exists
        if certificate_id not in self.certificates:
            raise Exception(f"SSH certificate {certificate_id} not found")

        # Add to KRL
        krl_entry = KRLEntry(
            serial_number=serial_number,
            revocation_time=revocation_data["revocation_time"],
            reason=revocation_data["reason"],
            certificate_fingerprint=self.certificates[certificate_id].get(
                "public_key_fingerprint"
            ),
        )

        self.revoked_certificates[serial_number] = krl_entry

        # Update certificate status
        self.certificates[certificate_id]["status"] = SSHCertificateStatus.REVOKED.value
        self.certificates[certificate_id]["revoked_at"] = revocation_data[
            "revocation_time"
        ].isoformat()

        # Invalidate caches
        cert_cache = self.cache_manager.get_cache("certificates")
        if cert_cache:
            await cert_cache.delete(certificate_id)

        krl_cache = self.cache_manager.get_cache("krl")
        if krl_cache:
            await krl_cache.clear()  # Clear all KRL cache

        # Schedule KRL update
        await self.krl_queue.put({"action": "update", "reason": "revocation"})

        self.metrics.certificates_revoked += 1

        logger.info(f"SSH certificate {certificate_id} revoked")

    async def _krl_processor_worker(self):
        """Worker for KRL generation"""
        logger.info("SSH KRL processor started")

        while self.running:
            try:
                # Wait for KRL update request or periodic update
                krl_request = await asyncio.wait_for(
                    self.krl_queue.get(), timeout=1800.0  # Update KRL every 30 minutes
                )

                await self._generate_krl()

            except asyncio.TimeoutError:
                # Periodic KRL update
                await self._generate_krl()
            except Exception as e:
                logger.error(f"SSH KRL processor error: {e}")

        logger.info("SSH KRL processor stopped")

    async def _generate_krl(self):
        """Generate Key Revocation List"""
        krl_data = await self.cpu_manager.submit_computation(self._generate_krl_sync)

        # Cache KRL
        krl_cache = self.cache_manager.get_cache("krl")
        if krl_cache:
            await krl_cache.set("current_krl", krl_data, ttl=1800.0)

        self.metrics.krl_updates += 1
        logger.info("SSH KRL generated and cached")

    def _generate_krl_sync(self) -> Dict[str, Any]:
        """Generate KRL synchronously"""
        # Simplified KRL generation
        krl_data = {
            "version": 1,
            "generated_at": datetime.utcnow().isoformat(),
            "ca_fingerprint": self.ca_fingerprint,
            "revoked_certificates": [],
        }

        # Add revoked certificates
        for serial_number, krl_entry in self.revoked_certificates.items():
            krl_data["revoked_certificates"].append(
                {
                    "serial_number": serial_number,
                    "revocation_time": krl_entry.revocation_time.isoformat(),
                    "reason": krl_entry.reason,
                    "fingerprint": krl_entry.certificate_fingerprint,
                }
            )

        return krl_data

    async def _config_processor_worker(self, worker_name: str):
        """Worker for SSH config generation"""
        logger.info(f"SSH config worker {worker_name} started")

        while self.running:
            try:
                config_request = await asyncio.wait_for(
                    self.config_queue.get(), timeout=1.0
                )

                await self._process_config_request(config_request, worker_name)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"SSH config worker {worker_name} error: {e}")
                self.metrics.error_count += 1

        logger.info(f"SSH config worker {worker_name} stopped")

    async def _process_config_request(
        self, config_request: Dict[str, Any], worker_name: str
    ):
        """Process SSH config generation request"""
        request_id = config_request["request_id"]
        config_type = config_request["config_type"]

        try:
            if config_type == "client_config":
                config_data = await self._generate_client_config(config_request)
            elif config_type == "server_config":
                config_data = await self._generate_server_config(config_request)
            elif config_type == "known_hosts":
                config_data = await self._generate_known_hosts(config_request)
            else:
                raise ValueError(f"Unknown config type: {config_type}")

            # Cache configuration
            config_cache = self.cache_manager.get_cache("ssh_configs")
            if config_cache:
                await config_cache.set(request_id, config_data, ttl=600.0)

            self.metrics.config_generations += 1

            logger.info(f"SSH config {request_id} generated by {worker_name}")

        except Exception as e:
            logger.error(f"Failed to generate SSH config {request_id}: {e}")
            self.metrics.error_count += 1
            raise

    async def _generate_client_config(self, config_request: Dict[str, Any]) -> str:
        """Generate SSH client configuration"""
        parameters = config_request["parameters"]
        user_id = config_request["user_id"]

        # Generate SSH client config
        config_lines = [
            "# SkausWatch SSH Client Configuration",
            f"# Generated for user: {user_id}",
            f"# Generated at: {datetime.utcnow().isoformat()}",
            "",
            "# Certificate authority public key",
            f"TrustedUserCAKeys ~/.ssh/ca_key.pub",
            "",
            "# Host configuration",
        ]

        # Add host-specific configurations
        hosts = parameters.get("hosts", [])
        for host in hosts:
            config_lines.extend(
                [
                    f"Host {host}",
                    f"    CertificateFile ~/.ssh/{user_id}_cert.pub",
                    f"    IdentityFile ~/.ssh/{user_id}_key",
                    "    IdentitiesOnly yes",
                    "",
                ]
            )

        return "\n".join(config_lines)

    async def _generate_server_config(self, config_request: Dict[str, Any]) -> str:
        """Generate SSH server configuration"""
        parameters = config_request["parameters"]

        config_lines = [
            "# SkausWatch SSH Server Configuration",
            f"# Generated at: {datetime.utcnow().isoformat()}",
            "",
            "# Certificate authority configuration",
            f"TrustedUserCAKeys /etc/ssh/ca_key.pub",
            f"HostCertificate /etc/ssh/host_cert.pub",
            f"HostKey /etc/ssh/host_key",
            "",
            "# Certificate-based authentication",
            "PubkeyAuthentication yes",
            "AuthorizedKeysFile none",
            "",
            "# Security settings",
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "ChallengeResponseAuthentication no",
            "UsePAM yes",
            "",
        ]

        # Add principals mapping if specified
        principals_mapping = parameters.get("principals_mapping", {})
        if principals_mapping:
            config_lines.extend(
                [
                    "# Principals mapping",
                    "AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u",
                    "",
                ]
            )

        return "\n".join(config_lines)

    async def _generate_known_hosts(self, config_request: Dict[str, Any]) -> str:
        """Generate known_hosts file"""
        parameters = config_request["parameters"]

        known_hosts_lines = [
            "# SkausWatch SSH Known Hosts",
            f"# Generated at: {datetime.utcnow().isoformat()}",
            "",
            "# Certificate authority public key",
            f"@cert-authority * {self.ca_public_key}",
            "",
        ]

        # Add host keys if specified
        host_keys = parameters.get("host_keys", [])
        for host_key_info in host_keys:
            hostname = host_key_info["hostname"]
            public_key = host_key_info["public_key"]
            known_hosts_lines.append(f"{hostname} {public_key}")

        return "\n".join(known_hosts_lines)

    async def _maintenance_worker(self):
        """Worker for maintenance tasks"""
        logger.info("SSH maintenance worker started")

        while self.running:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                await self._run_maintenance()

            except Exception as e:
                logger.error(f"SSH maintenance worker error: {e}")

        logger.info("SSH maintenance worker stopped")

    async def _run_maintenance(self):
        """Run maintenance tasks"""
        # Mark expired certificates
        now = datetime.utcnow()
        expired_count = 0

        for cert_data in self.certificates.values():
            if "valid_before" in cert_data:
                valid_before = cert_data["valid_before"]
                if isinstance(valid_before, str):
                    valid_before = datetime.fromisoformat(valid_before)

                if valid_before < now:
                    cert_data["status"] = SSHCertificateStatus.EXPIRED.value
                    expired_count += 1

        if expired_count > 0:
            logger.info(f"Marked {expired_count} SSH certificates as expired")

        # Update queue size metric
        self.metrics.queue_size = self.signing_queue.qsize()

        # Calculate cache hit rates
        cert_cache = self.cache_manager.get_cache("certificates")
        if cert_cache:
            stats = cert_cache.get_stats()
            if stats.hits + stats.misses > 0:
                self.metrics.cache_hit_rate = stats.hits / (stats.hits + stats.misses)

    async def get_metrics(self) -> SSHProcessingMetrics:
        """Get current processing metrics"""
        self.metrics.queue_size = self.signing_queue.qsize()
        return self.metrics

    async def get_ca_public_key(self) -> str:
        """Get CA public key"""
        return self.ca_public_key

    async def get_current_krl(self) -> Optional[Dict[str, Any]]:
        """Get current KRL"""
        krl_cache = self.cache_manager.get_cache("krl")
        if krl_cache:
            return await krl_cache.get("current_krl")
        return None

    @cache_decorator(cache_name="ssh_configs", ttl=600.0)
    async def get_ssh_config(self, request_id: str) -> Optional[str]:
        """Get generated SSH config"""
        config_cache = self.cache_manager.get_cache("ssh_configs")
        if config_cache:
            return await config_cache.get(request_id)
        return None

    async def list_certificates(
        self,
        certificate_type: Optional[SSHCertificateType] = None,
        status: Optional[SSHCertificateStatus] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List SSH certificates with filters"""
        certificates = []

        for cert_data in self.certificates.values():
            # Apply filters
            if (
                certificate_type
                and cert_data.get("certificate_type") != certificate_type.value
            ):
                continue
            if status and cert_data.get("status") != status.value:
                continue

            # Remove sensitive data
            safe_cert_data = {
                k: v for k, v in cert_data.items() if "private" not in k.lower()
            }
            certificates.append(safe_cert_data)

            if len(certificates) >= limit:
                break

        return certificates
