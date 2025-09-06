"""
Async Certificate Processing for SkausWatch PKI Server

Provides high-performance async certificate operations including generation,
validation, revocation, and OCSP/CRL management with background processing.
"""

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import uuid4
import json
import hashlib

# Cryptography imports
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import CertificatePoliciesOID, ExtensionOID

from ...shared.performance import (
    AsyncTaskManager, async_retry, async_timeout, async_batch_processor,
    ThreadPoolManager, TaskType, CPUBoundTaskManager,
    CacheManager, CacheConfig, cache_decorator,
    RateLimiter, RateLimitConfig, RateLimitStrategy
)

logger = logging.getLogger(__name__)


class CertificateStatus(Enum):
    """Certificate status enumeration"""
    PENDING = "pending"
    ISSUED = "issued"
    REVOKED = "revoked"
    EXPIRED = "expired"
    SUSPENDED = "suspended"


class RevocationReason(Enum):
    """Certificate revocation reasons"""
    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key_compromise"
    CA_COMPROMISE = "ca_compromise"
    AFFILIATION_CHANGED = "affiliation_changed"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"
    CERTIFICATE_HOLD = "certificate_hold"
    PRIVILEGE_WITHDRAWN = "privilege_withdrawn"
    AA_COMPROMISE = "aa_compromise"


@dataclass
class CertificateRequest:
    """Certificate request data"""
    request_id: str
    subject_dn: str
    san_list: List[str] = field(default_factory=list)
    key_size: int = 2048
    validity_days: int = 365
    certificate_profile: str = "default"
    requester_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "subject_dn": self.subject_dn,
            "san_list": self.san_list,
            "key_size": self.key_size,
            "validity_days": self.validity_days,
            "certificate_profile": self.certificate_profile,
            "requester_id": self.requester_id,
            "metadata": self.metadata
        }


@dataclass
class CertificateResponse:
    """Certificate response data"""
    certificate_id: str
    serial_number: str
    certificate_pem: str
    private_key_pem: Optional[str] = None
    certificate_chain_pem: Optional[str] = None
    status: CertificateStatus = CertificateStatus.ISSUED
    issued_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass 
class RevocationRequest:
    """Certificate revocation request"""
    certificate_id: str
    serial_number: str
    reason: RevocationReason
    revoked_by: str
    revocation_date: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProcessingMetrics:
    """Certificate processing metrics"""
    certificates_issued: int = 0
    certificates_revoked: int = 0
    ocsp_responses_generated: int = 0
    crl_updates: int = 0
    average_processing_time: float = 0.0
    processing_queue_size: int = 0
    cache_hit_rate: float = 0.0
    error_count: int = 0


class AsyncCertificateProcessor:
    """High-performance async certificate processor"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metrics = ProcessingMetrics()
        
        # Initialize managers
        self.task_manager = AsyncTaskManager()
        self.thread_pool_manager = ThreadPoolManager()
        self.cache_manager = CacheManager()
        
        # Certificate storage
        self.certificates: Dict[str, Dict[str, Any]] = {}
        self.revoked_certificates: Dict[str, Dict[str, Any]] = {}
        
        # Processing queues
        self.certificate_queue = asyncio.Queue(maxsize=1000)
        self.revocation_queue = asyncio.Queue(maxsize=500)
        self.ocsp_queue = asyncio.Queue(maxsize=2000)
        self.crl_queue = asyncio.Queue(maxsize=100)
        
        # Rate limiters
        self.rate_limiters = {}
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.running = False
        
    async def initialize(self):
        """Initialize the certificate processor"""
        # Start task manager
        await self.task_manager.start()
        
        # Create specialized thread pools
        cpu_bound_manager = CPUBoundTaskManager(self.thread_pool_manager)
        
        # Initialize caching
        cache_config = CacheConfig(
            max_size=10000,
            default_ttl=3600.0,  # 1 hour
            eviction_policy="lru",
            metrics_enabled=True
        )
        self.cache_manager.create_memory_cache("certificates", cache_config)
        self.cache_manager.create_memory_cache("ocsp_responses", CacheConfig(
            max_size=50000,
            default_ttl=300.0,  # 5 minutes for OCSP
            eviction_policy="lru"
        ))
        
        # Set up rate limiting
        self._setup_rate_limiters()
        
        # Load existing certificates (in production, this would be from database)
        await self._load_certificates()
        
        self.running = True
        
        # Start background processors
        await self._start_background_processors()
        
        logger.info("Async certificate processor initialized")
        
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
        
        logger.info("Certificate processor shutdown complete")
        
    def _setup_rate_limiters(self):
        """Setup rate limiters for different operations"""
        # Certificate issuance rate limiting
        self.rate_limiters['certificate_issue'] = RateLimiter(RateLimitConfig(
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            requests=100,  # 100 certificates per minute
            window_seconds=60.0,
            burst_size=20
        ))
        
        # OCSP request rate limiting
        self.rate_limiters['ocsp_request'] = RateLimiter(RateLimitConfig(
            strategy=RateLimitStrategy.SLIDING_WINDOW,
            requests=1000,  # 1000 OCSP requests per minute
            window_seconds=60.0
        ))
        
        # Revocation rate limiting
        self.rate_limiters['revocation'] = RateLimiter(RateLimitConfig(
            strategy=RateLimitStrategy.FIXED_WINDOW,
            requests=50,  # 50 revocations per minute
            window_seconds=60.0
        ))
        
    async def _load_certificates(self):
        """Load existing certificates from storage"""
        # In production, this would load from database
        # For now, initialize empty storage
        logger.info("Certificate storage initialized")
        
    async def _start_background_processors(self):
        """Start background processing tasks"""
        # Certificate processing workers
        for i in range(3):  # 3 certificate workers
            task = asyncio.create_task(
                self._certificate_processor_worker(f"cert-worker-{i}")
            )
            self.background_tasks.append(task)
            
        # Revocation processing worker
        task = asyncio.create_task(self._revocation_processor_worker())
        self.background_tasks.append(task)
        
        # OCSP response generator workers
        for i in range(2):  # 2 OCSP workers
            task = asyncio.create_task(
                self._ocsp_processor_worker(f"ocsp-worker-{i}")
            )
            self.background_tasks.append(task)
            
        # CRL generation worker
        task = asyncio.create_task(self._crl_processor_worker())
        self.background_tasks.append(task)
        
        # Maintenance worker
        task = asyncio.create_task(self._maintenance_worker())
        self.background_tasks.append(task)
        
        logger.info(f"Started {len(self.background_tasks)} background workers")
        
    @async_retry(max_attempts=3, delay=1.0)
    async def submit_certificate_request(self, request: CertificateRequest) -> str:
        """Submit certificate request for processing"""
        # Check rate limit
        rate_limiter = self.rate_limiters['certificate_issue']
        if not await rate_limiter.is_allowed(request.requester_id):
            raise Exception("Certificate issuance rate limit exceeded")
            
        # Add to processing queue
        await self.certificate_queue.put(request)
        
        self.metrics.processing_queue_size = self.certificate_queue.qsize()
        
        logger.info(f"Certificate request {request.request_id} queued for processing")
        return request.request_id
        
    async def submit_revocation_request(self, request: RevocationRequest) -> str:
        """Submit revocation request for processing"""
        # Check rate limit
        rate_limiter = self.rate_limiters['revocation']
        if not await rate_limiter.is_allowed(request.revoked_by):
            raise Exception("Revocation rate limit exceeded")
            
        # Add to processing queue
        await self.revocation_queue.put(request)
        
        logger.info(f"Revocation request for {request.certificate_id} queued")
        return request.certificate_id
        
    @cache_decorator(cache_name="certificates", ttl=3600.0)
    async def get_certificate(self, certificate_id: str) -> Optional[Dict[str, Any]]:
        """Get certificate by ID with caching"""
        return self.certificates.get(certificate_id)
        
    @cache_decorator(cache_name="ocsp_responses", ttl=300.0)
    async def get_ocsp_response(self, serial_number: str) -> Optional[bytes]:
        """Get OCSP response with caching"""
        # Generate OCSP response for certificate
        certificate = next(
            (cert for cert in self.certificates.values() 
             if cert.get('serial_number') == serial_number), 
            None
        )
        
        if not certificate:
            return None
            
        # Check if revoked
        is_revoked = serial_number in self.revoked_certificates
        
        # Generate OCSP response (simplified)
        ocsp_response = await self._generate_ocsp_response(
            serial_number, 
            certificate, 
            is_revoked
        )
        
        self.metrics.ocsp_responses_generated += 1
        return ocsp_response
        
    async def _certificate_processor_worker(self, worker_name: str):
        """Worker for processing certificate requests"""
        logger.info(f"Certificate worker {worker_name} started")
        
        while self.running:
            try:
                # Get request with timeout
                request = await asyncio.wait_for(
                    self.certificate_queue.get(),
                    timeout=1.0
                )
                
                await self._process_certificate_request(request, worker_name)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Certificate worker {worker_name} error: {e}")
                self.metrics.error_count += 1
                
        logger.info(f"Certificate worker {worker_name} stopped")
        
    async def _process_certificate_request(self, 
                                         request: CertificateRequest, 
                                         worker_name: str):
        """Process individual certificate request"""
        start_time = time.time()
        
        try:
            # Generate certificate in thread pool (CPU-bound)
            certificate_data = await self._generate_certificate_async(request)
            
            # Store certificate
            self.certificates[request.request_id] = {
                **certificate_data.to_dict() if hasattr(certificate_data, 'to_dict') else certificate_data,
                'processed_by': worker_name,
                'processed_at': datetime.utcnow().isoformat()
            }
            
            # Update metrics
            processing_time = time.time() - start_time
            self.metrics.certificates_issued += 1
            
            if self.metrics.average_processing_time == 0:
                self.metrics.average_processing_time = processing_time
            else:
                self.metrics.average_processing_time = (
                    self.metrics.average_processing_time * 0.9 + processing_time * 0.1
                )
                
            # Invalidate relevant caches
            cache = self.cache_manager.get_cache("certificates")
            if cache:
                await cache.delete(request.request_id)
                
            logger.info(
                f"Certificate {request.request_id} issued by {worker_name} "
                f"in {processing_time:.2f}s"
            )
            
        except Exception as e:
            logger.error(f"Failed to process certificate request {request.request_id}: {e}")
            self.metrics.error_count += 1
            raise
            
    @async_timeout(30.0)  # 30 second timeout
    async def _generate_certificate_async(self, request: CertificateRequest) -> Dict[str, Any]:
        """Generate certificate asynchronously using thread pool"""
        cpu_manager = CPUBoundTaskManager(self.thread_pool_manager)
        
        return await cpu_manager.submit_computation(
            self._generate_certificate_sync,
            request
        )
        
    def _generate_certificate_sync(self, request: CertificateRequest) -> Dict[str, Any]:
        """Generate certificate synchronously (CPU-bound operation)"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=request.key_size,
        )
        
        # Parse subject DN
        subject_parts = []
        for part in request.subject_dn.split(','):
            if '=' in part:
                key, value = part.strip().split('=', 1)
                if key.upper() == 'CN':
                    subject_parts.append(x509.NameAttribute(x509.NameOID.COMMON_NAME, value))
                elif key.upper() == 'O':
                    subject_parts.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, value))
                elif key.upper() == 'OU':
                    subject_parts.append(x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, value))
                elif key.upper() == 'C':
                    subject_parts.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, value))
                    
        subject = x509.Name(subject_parts)
        
        # Generate serial number
        serial_number = int.from_bytes(hashlib.sha256(
            f"{request.request_id}{time.time()}".encode()
        ).digest()[:8], 'big')
        
        # Build certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(subject)  # Self-signed for demo
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(serial_number)
        
        # Set validity period
        now = datetime.utcnow()
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=request.validity_days))
        
        # Add extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Add SAN extension if provided
        if request.san_list:
            san_list = []
            for san in request.san_list:
                if san.startswith('DNS:'):
                    san_list.append(x509.DNSName(san[4:]))
                elif san.startswith('IP:'):
                    import ipaddress
                    san_list.append(x509.IPAddress(ipaddress.ip_address(san[3:])))
                elif san.startswith('email:'):
                    san_list.append(x509.RFC822Name(san[6:]))
                    
            if san_list:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san_list),
                    critical=False
                )
                
        # Sign certificate
        certificate = builder.sign(private_key, hashes.SHA256())
        
        # Convert to PEM
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        return {
            'certificate_id': request.request_id,
            'serial_number': str(serial_number),
            'certificate_pem': cert_pem,
            'private_key_pem': key_pem,
            'status': CertificateStatus.ISSUED.value,
            'issued_at': now.isoformat(),
            'expires_at': (now + timedelta(days=request.validity_days)).isoformat(),
            'metadata': request.metadata
        }
        
    async def _revocation_processor_worker(self):
        """Worker for processing revocation requests"""
        logger.info("Revocation processor worker started")
        
        while self.running:
            try:
                request = await asyncio.wait_for(
                    self.revocation_queue.get(),
                    timeout=1.0
                )
                
                await self._process_revocation_request(request)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Revocation processor error: {e}")
                self.metrics.error_count += 1
                
        logger.info("Revocation processor worker stopped")
        
    async def _process_revocation_request(self, request: RevocationRequest):
        """Process certificate revocation"""
        # Check if certificate exists
        if request.certificate_id not in self.certificates:
            raise Exception(f"Certificate {request.certificate_id} not found")
            
        # Add to revoked certificates
        self.revoked_certificates[request.serial_number] = {
            'certificate_id': request.certificate_id,
            'serial_number': request.serial_number,
            'reason': request.reason.value,
            'revoked_by': request.revoked_by,
            'revocation_date': request.revocation_date.isoformat(),
            'metadata': request.metadata
        }
        
        # Update certificate status
        self.certificates[request.certificate_id]['status'] = CertificateStatus.REVOKED.value
        
        # Invalidate caches
        cache = self.cache_manager.get_cache("certificates")
        if cache:
            await cache.delete(request.certificate_id)
            
        ocsp_cache = self.cache_manager.get_cache("ocsp_responses")
        if ocsp_cache:
            await ocsp_cache.delete(request.serial_number)
            
        # Schedule CRL update
        await self.crl_queue.put({'action': 'update', 'reason': 'revocation'})
        
        self.metrics.certificates_revoked += 1
        
        logger.info(f"Certificate {request.certificate_id} revoked")
        
    async def _ocsp_processor_worker(self, worker_name: str):
        """Worker for processing OCSP requests"""
        logger.info(f"OCSP worker {worker_name} started")
        
        while self.running:
            try:
                # OCSP responses are generated on-demand via cache
                # This worker handles batch OCSP response pre-generation
                await asyncio.sleep(5.0)
                await self._pregenerate_ocsp_responses()
                
            except Exception as e:
                logger.error(f"OCSP worker {worker_name} error: {e}")
                
        logger.info(f"OCSP worker {worker_name} stopped")
        
    async def _pregenerate_ocsp_responses(self):
        """Pre-generate OCSP responses for active certificates"""
        # Get list of certificates that need OCSP responses
        active_certificates = [
            cert for cert in self.certificates.values()
            if cert.get('status') == CertificateStatus.ISSUED.value
        ]
        
        # Pre-generate responses for certificates without cached responses
        ocsp_cache = self.cache_manager.get_cache("ocsp_responses")
        if not ocsp_cache:
            return
            
        batch_size = 100
        for i in range(0, len(active_certificates), batch_size):
            batch = active_certificates[i:i + batch_size]
            
            for cert in batch:
                serial_number = cert.get('serial_number')
                if serial_number:
                    # Check if response is already cached
                    cached_response = await ocsp_cache.get(serial_number)
                    if cached_response is None:
                        # Generate and cache OCSP response
                        await self.get_ocsp_response(serial_number)
                        
    async def _generate_ocsp_response(self, 
                                    serial_number: str,
                                    certificate: Dict[str, Any],
                                    is_revoked: bool) -> bytes:
        """Generate OCSP response for certificate"""
        # This is a simplified OCSP response generation
        # In production, this would use proper OCSP libraries
        
        response_data = {
            'serial_number': serial_number,
            'status': 'revoked' if is_revoked else 'good',
            'this_update': datetime.utcnow().isoformat(),
            'next_update': (datetime.utcnow() + timedelta(hours=1)).isoformat()
        }
        
        if is_revoked and serial_number in self.revoked_certificates:
            revocation_info = self.revoked_certificates[serial_number]
            response_data['revocation_time'] = revocation_info['revocation_date']
            response_data['revocation_reason'] = revocation_info['reason']
            
        return json.dumps(response_data).encode()
        
    async def _crl_processor_worker(self):
        """Worker for CRL generation and updates"""
        logger.info("CRL processor worker started")
        
        while self.running:
            try:
                # Wait for CRL update request or timeout
                update_request = await asyncio.wait_for(
                    self.crl_queue.get(),
                    timeout=3600.0  # Update CRL every hour if no requests
                )
                
                await self._generate_crl()
                
            except asyncio.TimeoutError:
                # Periodic CRL update
                await self._generate_crl()
            except Exception as e:
                logger.error(f"CRL processor error: {e}")
                
        logger.info("CRL processor worker stopped")
        
    async def _generate_crl(self):
        """Generate Certificate Revocation List"""
        # Generate CRL in thread pool (CPU-bound)
        cpu_manager = CPUBoundTaskManager(self.thread_pool_manager)
        
        crl_data = await cpu_manager.submit_computation(
            self._generate_crl_sync
        )
        
        # Cache CRL
        cache = self.cache_manager.get_cache("certificates")
        if cache:
            await cache.set("current_crl", crl_data, ttl=3600.0)
            
        self.metrics.crl_updates += 1
        logger.info("CRL generated and cached")
        
    def _generate_crl_sync(self) -> Dict[str, Any]:
        """Generate CRL synchronously (CPU-bound operation)"""
        # This is a simplified CRL generation
        # In production, this would use proper X.509 CRL generation
        
        now = datetime.utcnow()
        
        crl_data = {
            'version': 1,
            'issuer': 'CN=SkausWatch CA',
            'this_update': now.isoformat(),
            'next_update': (now + timedelta(hours=24)).isoformat(),
            'revoked_certificates': []
        }
        
        # Add revoked certificates
        for serial_number, revocation_info in self.revoked_certificates.items():
            crl_data['revoked_certificates'].append({
                'serial_number': serial_number,
                'revocation_date': revocation_info['revocation_date'],
                'reason': revocation_info['reason']
            })
            
        return crl_data
        
    async def _maintenance_worker(self):
        """Worker for maintenance tasks"""
        logger.info("Maintenance worker started")
        
        while self.running:
            try:
                # Run maintenance every 5 minutes
                await asyncio.sleep(300)
                await self._run_maintenance()
                
            except Exception as e:
                logger.error(f"Maintenance worker error: {e}")
                
        logger.info("Maintenance worker stopped")
        
    async def _run_maintenance(self):
        """Run maintenance tasks"""
        # Clean up expired certificates
        now = datetime.utcnow()
        expired_count = 0
        
        for cert_id, cert_data in list(self.certificates.items()):
            expires_at_str = cert_data.get('expires_at')
            if expires_at_str:
                expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                if expires_at < now:
                    cert_data['status'] = CertificateStatus.EXPIRED.value
                    expired_count += 1
                    
        if expired_count > 0:
            logger.info(f"Marked {expired_count} certificates as expired")
            
        # Update queue size metric
        self.metrics.processing_queue_size = self.certificate_queue.qsize()
        
        # Calculate cache hit rates
        for cache_name in ["certificates", "ocsp_responses"]:
            cache = self.cache_manager.get_cache(cache_name)
            if cache:
                stats = cache.get_stats()
                if stats.hits + stats.misses > 0:
                    hit_rate = stats.hits / (stats.hits + stats.misses)
                    if cache_name == "certificates":
                        self.metrics.cache_hit_rate = hit_rate
                        
    async def get_metrics(self) -> ProcessingMetrics:
        """Get current processing metrics"""
        # Update queue size
        self.metrics.processing_queue_size = self.certificate_queue.qsize()
        
        return ProcessingMetrics(
            certificates_issued=self.metrics.certificates_issued,
            certificates_revoked=self.metrics.certificates_revoked,
            ocsp_responses_generated=self.metrics.ocsp_responses_generated,
            crl_updates=self.metrics.crl_updates,
            average_processing_time=self.metrics.average_processing_time,
            processing_queue_size=self.metrics.processing_queue_size,
            cache_hit_rate=self.metrics.cache_hit_rate,
            error_count=self.metrics.error_count
        )
        
    async def get_certificate_status(self, certificate_id: str) -> Optional[str]:
        """Get certificate status"""
        certificate = await self.get_certificate(certificate_id)
        return certificate.get('status') if certificate else None
        
    async def list_certificates(self, 
                              status: Optional[str] = None,
                              limit: int = 100) -> List[Dict[str, Any]]:
        """List certificates with optional status filter"""
        certificates = []
        
        for cert_data in self.certificates.values():
            if status is None or cert_data.get('status') == status:
                # Remove private key from response
                safe_cert_data = {k: v for k, v in cert_data.items() if k != 'private_key_pem'}
                certificates.append(safe_cert_data)
                
                if len(certificates) >= limit:
                    break
                    
        return certificates
        
    async def get_current_crl(self) -> Optional[Dict[str, Any]]:
        """Get current CRL"""
        cache = self.cache_manager.get_cache("certificates")
        if cache:
            return await cache.get("current_crl")
        return None